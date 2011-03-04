#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,re

import ptrace

from model import mapping,proc

# this use /proc/<pid>/maps + ptrace(2)

# linux only
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.memory_mapping import readProcessMappings

dbg=PtraceDebugger()
process=dbg.addProcess(8902,is_attached=False)
maps=readProcessMappings(process)

def getProcMaps():
   return "/proc/%s/maps"

PTRACE_PEEKDATA=2
PTRACE_ATTACH=9
PTRACE_DETACH=7

DBGMAP_READ=1
DBGMAP_WRITE=2
DBGMAP_EXEC=4
DBGMAP_SHARED=8


#FIXME
MIN_USER_PTR=0x00010000
MAX_USER_PTR=0xc0000000

dbg_verbose = 0



def parse_maps(proc):
  '''static int parse_maps(proc_t *p)'''

  path=getProcMaps()%proc.pid
  if not os.access(path,os.R_OK):
    log.error("can't read file %s"%(path))
    return None
  maps=[parse_line(line) for line in file(path).readlines()]
  proc.maps=maps
  return

#* maps helpers {{{ */

def dbg_map_lookup_by_address(proc,addr):
  '''mapping_t *dbg_map_lookup_by_address(
            proc_t *p,
            xaddr_t addr,
            unsigned int *off)
       return offset
  '''

  for m in proc.maps:
    if m.address > addr:
      break
    if (addr < (m.address + m.size)):
      offset = addr - m.address;
      return offset

  return None


def dbg_maps_lookup(proc,flags,name):
  '''int dbg_maps_lookup(
          proc_t *p,
          int flags,
          const char *name,
          mapping_t ***mappings)
  '''

  #log.error("maps_lookup(flags=%i, name=%s)\n"%(flags, name) )
  newmaps=[]
  for m in proc.maps:
    if (flags and (m.flags != flags)):
      continue
    if (name and (m.name != name)):
      continue
    log.debug("==> %s %s %s\n", m.name, name, m.name==name)
    #go
    newmaps.append(m)
  return newmaps


def dbg_map_lookup(proc, flags, name):
  '''mapping_t *dbg_map_lookup(proc_t *p, int flags, const char *name)'''
  maps = dbg_maps_lookup(proc, flags, name)
  log.debug("retcount: %d"%len(maps))
  if len(maps)==1:
    return maps[0]

  return None


def dbg_map_get_stack(proc):
  '''mapping_t *dbg_map_get_stack(proc_t *p)'''
  m = dbg_map_lookup(proc, DBGMAP_READ|DBGMAP_WRITE, "[stack]")
  if (m is None):
    m = dbg_map_lookup(proc, DBGMAP_READ|DBGMAP_WRITE|DBGMAP_EXEC, "[stack]")
  return m

def dbg_map_cache(mapping):
  '''int dbg_map_cache(mapping_t *map)'''

  if (mapping.data is not None):
    # // already mapped
    return mapping.data

  mapping.data = dbg_read(mapping.proc, mapping.address,mapping.size);
  if (mapping.data is None):
    log.error("error: failed to read %d bytes"% mapping.size)

  return mapping.data


/* open/close {{{ */

static proc_t *ptraced_proc = NULL;

static void killme(int sig, siginfo_t *si, void *bla)
{
  if (sig == SIGCHLD) {
    if (dbg_verbose)
      fprintf(stderr, "dbg: attached to process %u\n", si->si_pid);
    return;
  }  
  dbg_detach(ptraced_proc);
  ptraced_proc = NULL;
  fprintf(stderr, "killed\n");
  exit(0);
}  



int dbg_init(proc_t *p, pid_t pid)
{
  int ret;
  unsigned int i;
  struct sigaction sa;

  if (ptraced_proc)
    return DBGERR_NOT_IMPLEMENTED; /* TODO */
  
  if (!pid || (pid == getpid()) || (pid == getppid()))
    return DBGERR_BAD_PID;
  

  ret = parse_maps(p);
  if (ret) {
    ptraced_proc = NULL;
    return ret;
  }

  /* catch signals to avoid leaving the child ptraced */
  memset(&sa, 0, sizeof(sa));
  for (i=1; i<_NSIG-1; ++i) { /* FIXME */
    sa.sa_flags    = SA_SIGINFO;
    sa.sa_sigaction = killme;
    switch (i) {
      case SIGKILL:
      case SIGSTOP:
        break;
      default:
        sigaction(i, &sa, NULL);
    }
  }

  return 0;
}

void dbg_exit(proc_t *p)
{
  mapping_t *tmp, *next;

  for (tmp=p->maps; tmp; tmp=next) {
    if (tmp->data)
      free(tmp->data);
    next = tmp->next;
    free(tmp);
  }
  memset(p, 0, sizeof(*p));
}

/* }}} */

/* attach / detach {{{ */

int dbg_attach(proc_t *p, int mode)
{
#ifdef DBG_DARWIN
    // no ptrace needed to dump memory
#elif defined(DBG_SOLARIS) 
  char path[64];

  snprintf(path, sizeof(path)-1, "/proc/%s/as", p->pid_str);
  p->mem_fd = open(path, O_RDONLY);
  if (p->mem_fd < 0) {
    perror("open");
    return -1;
  }
#else
  int status;
  
  if (p->flags & DBGPROC_TRACED)
    return DBGERR_ALREADY_ATTACHED;

  p->flags |= DBGPROC_TRACED;


#if defined(DBG_HPUX)
  if (ttrace(TT_PROC_ATTACH, p->pid, 0, 0, TT_VERSION, 0)) {
#elif defined(DBG_LINUX)
  if (ptrace(PTRACE_ATTACH, p->pid, 0, 0)) {
#elif defined(DBG_FREEBSD) || defined(DBG_NETBSD) || defined(DBG_OPENBSD)
  if (ptrace(PT_ATTACH, p->pid, 0, 0)) {
#elif defined(DBG_MACOSX)
  if (ptrace(PT_ATTACH, p->pid, 0, 0, 0)) {
#elif defined(DBG_SOLARIS)
  printf("toto\n");
  if (ptrace(9, p->pid, 0, 0)) {
#endif
    p->flags &= ~DBGPROC_TRACED;
    if (errno == EPERM)
      return DBGERR_ENOPERM;
#ifndef DBG_HPUX
    perror("ptrace");
#else
    perror("ttrace");
#endif
    return -1;
  }

#ifndef DBG_HPUX
  /* all OS with ptrace interface */

  /* wait ptraced child to stop */
  alarm(5);
  wait(&status);
  alarm(0);

  if (!WIFSTOPPED(status)) {
    dbg_detach(p);
    return DBGERR_TARGET_KILLED;
  }
#endif // DBG_HPUX
#endif
  return 0;
}

void dbg_detach(proc_t *p)
{
  if (p->flags & DBGPROC_TRACED) {
#if defined(DBG_LINUX)
    ptrace(PTRACE_DETACH, p->pid, 0, 0);
#elif defined(DBG_SOLARIS)
    //ptrace(PTRACE_DETACH, p->pid, 1, 0);
    close(p->mem_fd);
    p->mem_fd = -1;
#elif defined(DBG_FREEBSD) || defined(DBG_NETBSD) || defined(DBG_OPENBSD)
    ptrace(PT_DETACH, p->pid, 0, 0);
#elif defined(DBG_HPUX)
    ttrace(TT_PROC_DETACH, pid, 0, 0, 0, 0);
#endif
    p->flags &= ~DBGPROC_TRACED;
    if (dbg_verbose)
      fprintf(stdout, "dbg: detached from process %u\n", p->pid);
  }
}

/* }}} */

/* get/set registers {{{ */
int dbg_get_regs(proc_t *p, void *regs)
{
#if defined(DBG_LINUX)
  return ptrace(PTRACE_GETREGS, p->pid, NULL, regs);
#else
  return DBGERR_NOT_IMPLEMENTED; /* TODO */
#endif
}

int dbg_set_regs(proc_t *p, const void *regs)
{
#if defined(DBG_LINUX)
  return ptrace(PTRACE_SETREGS, p->pid, NULL, regs);
#else
  return DBGERR_NOT_IMPLEMENTED; /* TODO */
#endif
}
/* }}} */

int dbg_continue(proc_t *p)
{
#if defined(DBG_LINUX)
  return ptrace(PTRACE_CONT, p->pid, NULL, NULL);
#else
  return DBGERR_NOT_IMPLEMENTED; /* TODO */
#endif
}

char *dbg_get_binpath(proc_t *p)
{
#if defined(DBG_LINUX)
  ssize_t ret;
  size_t len;
  char *bak, *real_path, path[64];

  snprintf(path, 63, "/proc/%s/exe", p->pid_str);
  path[63] = 0;

  len = 0;
  real_path = NULL;
  do {
    bak = real_path;
    real_path = realloc(real_path, len+256);
    if (!real_path) {
      if (bak)
        free(bak);
      return NULL;
    }
    len += 256;

    ret = readlink(path, real_path, len-1);
    if (ret > 0) {
      real_path[ret] = 0;
      return real_path;
    }
  } while (errno == ENAMETOOLONG);
  return NULL;
#else
  return NULL;
#endif
}

/* read/write mem {{{ */

int dbg_read(proc_t *p, xaddr_t addr, void *buf, unsigned int size)
{
#if defined(DBG_HPUX)
    return ttrace(TTRACE_READ, p->pid, 0, addr, size, buf);
#elif defined(DBG_DARWIN)
    unsigned int tmp = size;

    task_t task;

    if ( task_for_pid(current_task(), p->pid, &task) != KERN_SUCCESS ) {
        printf("task_for_pid error\n");
        return -1;
    }

    kern_return_t res = vm_read_overwrite(task, addr, size, (unsigned long) buf, &tmp);
    switch(res) {
        case KERN_SUCCESS:
            return 0;
        case KERN_PROTECTION_FAILURE:
            fprintf(stderr, "KERN_PROTECTION_FAILURE %p\n", (void *) addr);
            return -1;
        case KERN_INVALID_ADDRESS:
            fprintf(stderr, "KERN_INVALID_ADDRESS %p\n", (void *) addr);
            return -1;
    }
    printf("unknown return value %d @%p\n", res, (void *) addr);
    return -1;
#elif defined(DBG_SOLARIS)
    ssize_t ret;

    if (lseek(p->mem_fd, (off_t)addr, SEEK_SET) != (off_t)addr) {
        perror("lseek");
        return -1;
    }
    ret = read(p->mem_fd, buf, size);
    if (ret < 0)
        return -1;
    return size != (unsigned int) ret; 

#elif defined(DBG_WIN)
    DWORD len;

    len = 0;
    if (ReadProcessMemory(p->handle, addr, buf, (DWORD)size, &len))
        return 0;
    return win_to_dbgerr();
#else
    unsigned int i;
    long ret, *out;

    for (i=0, out=(long*)buf; i<size; i+=sizeof(long), ++out) {
        errno = 0;

#if defined(DBG_LINUX) || defined(DBG_SOLARIS)
        ret = ptrace(PTRACE_PEEKDATA, p->pid, addr+i, 1);
#elif defined(DBG_FREEBSD) || defined(DBG_OPENBSD) || defined(DBG_NETBSD)
        ret = ptrace(PT_READ_D, p->pid, (caddr_t)(addr+i), 0);
#elif defined(DBG_MACOSX)
        ret = ptrace(PT_READ_D, p->pid, addr+i, 0, 0);
#endif
        if ((ret == -1) && errno) {
            fprintf(stderr, "error: cannot fetch word @ 0x%lx\n", addr+i);
            if (errno == ESRCH) {
                /* ESRCH also means access denied ! */
                fprintf(stderr,
                        "ptrace: access denied or process has terminated\n");
            } else {
                perror("ptrace");
            }
            return -1;
        }
        *out = ret;
    }
    return 0;
#endif
}
/* }}} */

/* read helpers {{{ */
void *dbg_xlate_ptr(proc_t *p, xaddr_t addr)
{
  mapping_t *map;
  unsigned int off;

  map = dbg_map_lookup_by_address(p, addr, &off);
  if (!map)
    return NULL;
  if ((addr < map->address)
      || (addr > (map->address + map->size - 4))) {
    return NULL;
  }

  return map->data + off;
}

int dbg_read_ptr(proc_t *p, xaddr_t addr, xaddr_t *v)
{
  if (!(p->flags & DBGPROC_TRACED))
    return DBGERR_NOT_ATTACHED;

  /* FIXME : ptr size .. 32/64 */
  return dbg_read(p, addr, v, sizeof(*v));
}

int dbg_get_memory(proc_t *p) {

   mapping_t * map;
   int error = 0;
   dbg_map_for_each(p, map) {

      if (((map->flags & (DBGMAP_READ|DBGMAP_WRITE)) != (DBGMAP_READ|DBGMAP_WRITE))
    || (map->flags & DBGMAP_SHARED))
        continue;

  if (dbg_map_cache(map)) {
        fprintf(stderr, "error reading %d bytes at %p\n", map->size, (void *)map->address);
     error = 1;
  }
   }

  return error;
}
/* }}} */

// vim: ts=3 sw=3 fdm=marker
