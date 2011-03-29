from ctypes import *

STRING = c_char_p


__s8 = c_byte
__u8 = c_ubyte
__s16 = c_short
__u16 = c_ushort
__s32 = c_int
__u32 = c_uint
__s64 = c_longlong
__u64 = c_ulonglong
s8 = c_byte
u8 = c_ubyte
s16 = c_short
u16 = c_ushort
s32 = c_int
u32 = c_uint
s64 = c_longlong
u64 = c_ulonglong
umode_t = c_ushort
dma64_addr_t = u64
dma_addr_t = u64
__kernel_sighandler_t = CFUNCTYPE(None, c_int)
__kernel_key_t = c_int
__kernel_mqd_t = c_int
__kernel_ino_t = c_ulong
__kernel_mode_t = c_ushort
__kernel_nlink_t = c_ushort
__kernel_off_t = c_long
__kernel_pid_t = c_int
__kernel_ipc_pid_t = c_ushort
__kernel_uid_t = c_ushort
__kernel_gid_t = c_ushort
__kernel_size_t = c_uint
__kernel_ssize_t = c_int
__kernel_ptrdiff_t = c_int
__kernel_time_t = c_long
__kernel_suseconds_t = c_long
__kernel_clock_t = c_long
__kernel_timer_t = c_int
__kernel_clockid_t = c_int
__kernel_daddr_t = c_int
__kernel_caddr_t = STRING
__kernel_uid16_t = c_ushort
__kernel_gid16_t = c_ushort
__kernel_uid32_t = c_uint
__kernel_gid32_t = c_uint
__kernel_old_uid_t = c_ushort
__kernel_old_gid_t = c_ushort
__kernel_old_dev_t = c_ushort
__kernel_loff_t = c_longlong
__kernel_dev_t = __u32
class __kernel_fd_set(Structure):
    pass
fd_set = __kernel_fd_set
dev_t = __kernel_dev_t
ino_t = __kernel_ino_t
mode_t = __kernel_mode_t
nlink_t = __kernel_nlink_t
off_t = __kernel_off_t
pid_t = __kernel_pid_t
daddr_t = __kernel_daddr_t
key_t = __kernel_key_t
suseconds_t = __kernel_suseconds_t
timer_t = __kernel_timer_t
clockid_t = __kernel_clockid_t
mqd_t = __kernel_mqd_t
uid_t = __kernel_uid32_t
gid_t = __kernel_gid32_t
uid16_t = __kernel_uid16_t
gid16_t = __kernel_gid16_t
uintptr_t = c_ulong
old_uid_t = __kernel_old_uid_t
old_gid_t = __kernel_old_gid_t
loff_t = __kernel_loff_t
size_t = __kernel_size_t
ssize_t = __kernel_ssize_t
ptrdiff_t = __kernel_ptrdiff_t
time_t = __kernel_time_t
clock_t = __kernel_clock_t
caddr_t = __kernel_caddr_t
u_char = c_ubyte
u_short = c_ushort
u_int = c_uint
u_long = c_ulong
unchar = c_ubyte
ushort = c_ushort
uint = c_uint
ulong = c_ulong
u_int8_t = __u8
int8_t = __s8
u_int16_t = __u16
int16_t = __s16
u_int32_t = __u32
int32_t = __s32
uint8_t = __u8
uint16_t = __u16
uint32_t = __u32
uint64_t = __u64
u_int64_t = __u64
int64_t = __s64
sector_t = u64
blkcnt_t = u64
__le16 = __u16
__be16 = __u16
__le32 = __u32
__be32 = __u32
__le64 = __u64
__be64 = __u64
__sum16 = __u16
__wsum = __u32
gfp_t = c_uint
fmode_t = c_uint
phys_addr_t = u64
resource_size_t = phys_addr_t
class __user_cap_header_struct(Structure):
    pass
cap_user_header_t = POINTER(__user_cap_header_struct)
class __user_cap_data_struct(Structure):
    pass
cap_user_data_t = POINTER(__user_cap_data_struct)
class kernel_cap_struct(Structure):
    pass
kernel_cap_t = kernel_cap_struct
__gnuc_va_list = STRING
va_list = __gnuc_va_list
initcall_t = CFUNCTYPE(c_int)
exitcall_t = CFUNCTYPE(None)
ctor_fn_t = CFUNCTYPE(None)
pteval_t = u64
pmdval_t = u64
pudval_t = u64
pgdval_t = u64
pgprotval_t = u64
class pgprot(Structure):
    pass
pgprot_t = pgprot
class page(Structure):
    pass
pgtable_t = POINTER(page)
class desc_struct(Structure):
    pass
gate_desc = desc_struct
ldt_desc = desc_struct
tss_desc = desc_struct
class cpumask(Structure):
    pass
cpumask_t = cpumask
cpumask._fields_ = [
    ('bits', c_ulong * 1),
]
cpumask_var_t = cpumask * 1
class pt_regs(Structure):
    pass
handler_t = CFUNCTYPE(None, c_int, POINTER(pt_regs))
class atomic_t(Structure):
    pass
atomic_long_t = atomic_t
class arch_spinlock(Structure):
    pass
arch_spinlock_t = arch_spinlock
class raw_spinlock(Structure):
    pass
raw_spinlock_t = raw_spinlock
class spinlock(Structure):
    pass
spinlock_t = spinlock
class seqcount(Structure):
    pass
seqcount_t = seqcount
cycles_t = c_ulonglong
class rb_node(Structure):
    pass
rb_augment_f = CFUNCTYPE(None, POINTER(rb_node), c_void_p)
rwsem_count_t = c_long
class __wait_queue(Structure):
    pass
wait_queue_t = __wait_queue
wait_queue_func_t = CFUNCTYPE(c_int, POINTER(wait_queue_t), c_uint, c_int, c_void_p)
class __wait_queue_head(Structure):
    pass
wait_queue_head_t = __wait_queue_head
cputime_t = c_ulong
cputime64_t = u64
apm_event_t = c_ushort
apm_eventinfo_t = c_ushort
class physid_mask(Structure):
    pass
physid_mask_t = physid_mask
class ktime(Union):
    pass
ktime_t = ktime
class work_struct(Structure):
    pass
work_func_t = CFUNCTYPE(None, POINTER(work_struct))
class pm_message(Structure):
    pass
pm_message_t = pm_message
old_sigset_t = c_ulong
__signalfn_t = CFUNCTYPE(None, c_int)
__sighandler_t = POINTER(__signalfn_t)
__restorefn_t = CFUNCTYPE(None)
__sigrestore_t = POINTER(__restorefn_t)
class sigaltstack(Structure):
    pass
stack_t = sigaltstack
class sigval(Union):
    pass
sigval_t = sigval
class siginfo(Structure):
    pass
siginfo_t = siginfo
class sigevent(Structure):
    pass
sigevent_t = sigevent
pcpu_fc_alloc_fn_t = CFUNCTYPE(c_void_p, c_uint, size_t, size_t)
pcpu_fc_free_fn_t = CFUNCTYPE(None, c_void_p, size_t)
pcpu_fc_populate_pte_fn_t = CFUNCTYPE(None, c_ulong)
pcpu_fc_cpu_distance_fn_t = CFUNCTYPE(c_int, c_uint, c_uint)
class pglist_data(Structure):
    pass
pg_data_t = pglist_data
class ctl_table(Structure):
    pass
key_serial_t = int32_t
key_perm_t = uint32_t
class __key_reference_with_attributes(Structure):
    pass
key_ref_t = POINTER(__key_reference_with_attributes)
aio_context_t = c_ulong
__kernel_fd_set._fields_ = [
    ('fds_bits', c_ulong * 32),
]
atomic_t._fields_ = [
    ('counter', c_int),
]
__user_cap_header_struct._fields_ = [
    ('version', __u32),
    ('pid', c_int),
]
__user_cap_data_struct._fields_ = [
    ('effective', __u32),
    ('permitted', __u32),
    ('inheritable', __u32),
]
kernel_cap_struct._fields_ = [
    ('cap', __u32 * 2),
]
pt_regs._fields_ = [
    ('bx', c_ulong),
    ('cx', c_ulong),
    ('dx', c_ulong),
    ('si', c_ulong),
    ('di', c_ulong),
    ('bp', c_ulong),
    ('ax', c_ulong),
    ('ds', c_ulong),
    ('es', c_ulong),
    ('fs', c_ulong),
    ('gs', c_ulong),
    ('orig_ax', c_ulong),
    ('ip', c_ulong),
    ('cs', c_ulong),
    ('flags', c_ulong),
    ('sp', c_ulong),
    ('ss', c_ulong),
]
pgprot._pack_ = 4
pgprot._fields_ = [
    ('pgprot', pgprotval_t),
]
class N11desc_struct4DOT_24E(Union):
    pass
class N11desc_struct4DOT_244DOT_25E(Structure):
    pass
N11desc_struct4DOT_244DOT_25E._fields_ = [
    ('a', c_uint),
    ('b', c_uint),
]
class N11desc_struct4DOT_244DOT_26E(Structure):
    pass
N11desc_struct4DOT_244DOT_26E._fields_ = [
    ('limit0', u16),
    ('base0', u16),
    ('base1', c_uint, 8),
    ('type', c_uint, 4),
    ('s', c_uint, 1),
    ('dpl', c_uint, 2),
    ('p', c_uint, 1),
    ('limit', c_uint, 4),
    ('avl', c_uint, 1),
    ('l', c_uint, 1),
    ('d', c_uint, 1),
    ('g', c_uint, 1),
    ('base2', c_uint, 8),
]
N11desc_struct4DOT_24E._anonymous_ = ['_1', '_0']
N11desc_struct4DOT_24E._fields_ = [
    ('_0', N11desc_struct4DOT_244DOT_25E),
    ('_1', N11desc_struct4DOT_244DOT_26E),
]
desc_struct._pack_ = 1
desc_struct._anonymous_ = ['_0']
desc_struct._fields_ = [
    ('_0', N11desc_struct4DOT_24E),
]
arch_spinlock._fields_ = [
    ('slock', c_uint),
]
raw_spinlock._fields_ = [
    ('raw_lock', arch_spinlock_t),
]
class N8spinlock4DOT_40E(Union):
    pass
N8spinlock4DOT_40E._fields_ = [
    ('rlock', raw_spinlock),
]
spinlock._anonymous_ = ['_0']
spinlock._fields_ = [
    ('_0', N8spinlock4DOT_40E),
]
seqcount._fields_ = [
    ('sequence', c_uint),
]
rb_node._fields_ = [
    ('rb_parent_color', c_ulong),
    ('rb_right', POINTER(rb_node)),
    ('rb_left', POINTER(rb_node)),
]
class list_head(Structure):
    pass
list_head._fields_ = [
    ('next', POINTER(list_head)),
    ('prev', POINTER(list_head)),
]
__wait_queue._fields_ = [
    ('flags', c_uint),
    ('private_', c_void_p),
    ('func', wait_queue_func_t),
    ('task_list', list_head),
]
__wait_queue_head._fields_ = [
    ('lock', spinlock_t),
    ('task_list', list_head),
]
class N4page4DOT_45E(Union):
    pass
class N4page4DOT_454DOT_46E(Structure):
    pass
N4page4DOT_454DOT_46E._fields_ = [
    ('inuse', u16),
    ('objects', u16),
]
N4page4DOT_45E._anonymous_ = ['_0']
N4page4DOT_45E._fields_ = [
    ('_mapcount', atomic_t),
    ('_0', N4page4DOT_454DOT_46E),
]
class N4page4DOT_47E(Union):
    pass
class N4page4DOT_474DOT_48E(Structure):
    pass
class address_space(Structure):
    pass
N4page4DOT_474DOT_48E._fields_ = [
    ('private_', c_ulong),
    ('mapping', POINTER(address_space)),
]
class kmem_cache(Structure):
    pass
N4page4DOT_47E._anonymous_ = ['_0']
N4page4DOT_47E._fields_ = [
    ('_0', N4page4DOT_474DOT_48E),
    ('ptl', spinlock_t),
    ('slab', POINTER(kmem_cache)),
    ('first_page', POINTER(page)),
]
class N4page4DOT_49E(Union):
    pass
N4page4DOT_49E._fields_ = [
    ('index', c_ulong),
    ('freelist', c_void_p),
]
page._anonymous_ = ['_1', '_2', '_0']
page._fields_ = [
    ('flags', c_ulong),
    ('_count', atomic_t),
    ('_0', N4page4DOT_45E),
    ('_1', N4page4DOT_47E),
    ('_2', N4page4DOT_49E),
    ('lru', list_head),
]
physid_mask._fields_ = [
    ('mask', c_ulong * 8),
]
ktime._pack_ = 4
ktime._fields_ = [
    ('tv64', s64),
]
work_struct._fields_ = [
    ('data', atomic_long_t),
    ('entry', list_head),
    ('func', work_func_t),
]
pm_message._fields_ = [
    ('event', c_int),
]
sigaltstack._fields_ = [
    ('ss_sp', c_void_p),
    ('ss_flags', c_int),
    ('ss_size', size_t),
]
sigval._fields_ = [
    ('sival_int', c_int),
    ('sival_ptr', c_void_p),
]
class N7siginfo5DOT_124E(Union):
    pass
class N7siginfo5DOT_1245DOT_125E(Structure):
    pass
N7siginfo5DOT_1245DOT_125E._fields_ = [
    ('_pid', __kernel_pid_t),
    ('_uid', __kernel_uid32_t),
]
class N7siginfo5DOT_1245DOT_126E(Structure):
    pass
N7siginfo5DOT_1245DOT_126E._fields_ = [
    ('_tid', __kernel_timer_t),
    ('_overrun', c_int),
    ('_pad', c_char * 0),
    ('_sigval', sigval_t),
    ('_sys_private', c_int),
]
class N7siginfo5DOT_1245DOT_127E(Structure):
    pass
N7siginfo5DOT_1245DOT_127E._fields_ = [
    ('_pid', __kernel_pid_t),
    ('_uid', __kernel_uid32_t),
    ('_sigval', sigval_t),
]
class N7siginfo5DOT_1245DOT_128E(Structure):
    pass
N7siginfo5DOT_1245DOT_128E._fields_ = [
    ('_pid', __kernel_pid_t),
    ('_uid', __kernel_uid32_t),
    ('_status', c_int),
    ('_utime', __kernel_clock_t),
    ('_stime', __kernel_clock_t),
]
class N7siginfo5DOT_1245DOT_129E(Structure):
    pass
N7siginfo5DOT_1245DOT_129E._fields_ = [
    ('_addr', c_void_p),
    ('_addr_lsb', c_short),
]
class N7siginfo5DOT_1245DOT_130E(Structure):
    pass
N7siginfo5DOT_1245DOT_130E._fields_ = [
    ('_band', c_long),
    ('_fd', c_int),
]
N7siginfo5DOT_124E._fields_ = [
    ('_pad', c_int * 29),
    ('_kill', N7siginfo5DOT_1245DOT_125E),
    ('_timer', N7siginfo5DOT_1245DOT_126E),
    ('_rt', N7siginfo5DOT_1245DOT_127E),
    ('_sigchld', N7siginfo5DOT_1245DOT_128E),
    ('_sigfault', N7siginfo5DOT_1245DOT_129E),
    ('_sigpoll', N7siginfo5DOT_1245DOT_130E),
]
siginfo._fields_ = [
    ('si_signo', c_int),
    ('si_errno', c_int),
    ('si_code', c_int),
    ('_sifields', N7siginfo5DOT_124E),
]
class N8sigevent5DOT_131E(Union):
    pass
class N8sigevent5DOT_1315DOT_132E(Structure):
    pass
N8sigevent5DOT_1315DOT_132E._fields_ = [
    ('_function', CFUNCTYPE(None, sigval_t)),
    ('_attribute', c_void_p),
]
N8sigevent5DOT_131E._fields_ = [
    ('_pad', c_int * 13),
    ('_tid', c_int),
    ('_sigev_thread', N8sigevent5DOT_1315DOT_132E),
]
sigevent._fields_ = [
    ('sigev_value', sigval_t),
    ('sigev_signo', c_int),
    ('sigev_notify', c_int),
    ('_sigev_un', N8sigevent5DOT_131E),
]
class zone(Structure):
    pass
class per_cpu_pageset(Structure):
    pass
class free_area(Structure):
    pass
free_area._fields_ = [
    ('free_list', list_head * 5),
    ('nr_free', c_ulong),
]
class zone_padding(Structure):
    pass
zone_padding._fields_ = [
    ('x', c_char * 0),
]
class zone_lru(Structure):
    pass
zone_lru._fields_ = [
    ('list', list_head),
]
class zone_reclaim_stat(Structure):
    pass
zone_reclaim_stat._fields_ = [
    ('recent_rotated', c_ulong * 2),
    ('recent_scanned', c_ulong * 2),
    ('nr_saved_scan', c_ulong * 5),
]
zone._fields_ = [
    ('watermark', c_ulong * 3),
    ('percpu_drift_mark', c_ulong),
    ('lowmem_reserve', c_ulong * 4),
    ('pageset', POINTER(per_cpu_pageset)),
    ('lock', spinlock_t),
    ('all_unreclaimable', c_int),
    ('free_area', free_area * 11),
    ('pageblock_flags', POINTER(c_ulong)),
    ('_pad1_', zone_padding),
    ('lru_lock', spinlock_t),
    ('lru', zone_lru * 5),
    ('reclaim_stat', zone_reclaim_stat),
    ('pages_scanned', c_ulong),
    ('flags', c_ulong),
    ('vm_stat', atomic_long_t * 23),
    ('prev_priority', c_int),
    ('inactive_ratio', c_uint),
    ('_pad2_', zone_padding),
    ('wait_table', POINTER(wait_queue_head_t)),
    ('wait_table_hash_nr_entries', c_ulong),
    ('wait_table_bits', c_ulong),
    ('zone_pgdat', POINTER(pglist_data)),
    ('zone_start_pfn', c_ulong),
    ('spanned_pages', c_ulong),
    ('present_pages', c_ulong),
    ('name', STRING),
]
class zonelist(Structure):
    pass
class zonelist_cache(Structure):
    pass
class zoneref(Structure):
    pass
zoneref._fields_ = [
    ('zone', POINTER(zone)),
    ('zone_idx', c_int),
]
zonelist._fields_ = [
    ('zlcache_ptr', POINTER(zonelist_cache)),
    ('_zonerefs', zoneref * 5),
]
class page_cgroup(Structure):
    pass
class task_struct(Structure):
    pass
pglist_data._fields_ = [
    ('node_zones', zone * 4),
    ('node_zonelists', zonelist * 1),
    ('nr_zones', c_int),
    ('node_mem_map', POINTER(page)),
    ('node_page_cgroup', POINTER(page_cgroup)),
    ('node_start_pfn', c_ulong),
    ('node_present_pages', c_ulong),
    ('node_spanned_pages', c_ulong),
    ('node_id', c_int),
    ('kswapd_wait', wait_queue_head_t),
    ('kswapd', POINTER(task_struct)),
    ('kswapd_max_order', c_int),
]
ctl_table._fields_ = [
    ('procname', STRING),
    ('data', c_void_p),
    ('maxlen', c_int),
    ('mode', mode_t),
    ('child', POINTER(ctl_table)),
    ('parent', POINTER(ctl_table)),
    ('proc_handler', POINTER(c_int)),
    ('extra1', c_void_p),
    ('extra2', c_void_p),
]
__key_reference_with_attributes._fields_ = [
]
kmem_cache._fields_ = [
]
address_space._fields_ = [
]
class per_cpu_pages(Structure):
    pass
per_cpu_pages._fields_ = [
    ('count', c_int),
    ('high', c_int),
    ('batch', c_int),
    ('lists', list_head * 3),
]
per_cpu_pageset._fields_ = [
    ('pcp', per_cpu_pages),
    ('stat_threshold', s8),
    ('vm_stat_diff', s8 * 23),
]
zonelist_cache._fields_ = [
]
page_cgroup._fields_ = [
]
class sched_class(Structure):
    pass
class rq(Structure):
    pass
sched_class._fields_ = [
    ('next', POINTER(sched_class)),
    ('enqueue_task', CFUNCTYPE(None, POINTER(rq), POINTER(task_struct), c_int)),
    ('dequeue_task', CFUNCTYPE(None, POINTER(rq), POINTER(task_struct), c_int)),
    ('yield_task', CFUNCTYPE(None, POINTER(rq))),
    ('check_preempt_curr', CFUNCTYPE(None, POINTER(rq), POINTER(task_struct), c_int)),
    ('pick_next_task', CFUNCTYPE(POINTER(task_struct), POINTER(rq))),
    ('put_prev_task', CFUNCTYPE(None, POINTER(rq), POINTER(task_struct))),
    ('select_task_rq', CFUNCTYPE(c_int, POINTER(rq), POINTER(task_struct), c_int, c_int)),
    ('pre_schedule', CFUNCTYPE(None, POINTER(rq), POINTER(task_struct))),
    ('post_schedule', CFUNCTYPE(None, POINTER(rq))),
    ('task_waking', CFUNCTYPE(None, POINTER(rq), POINTER(task_struct))),
    ('task_woken', CFUNCTYPE(None, POINTER(rq), POINTER(task_struct))),
    ('set_cpus_allowed', CFUNCTYPE(None, POINTER(task_struct), POINTER(cpumask))),
    ('rq_online', CFUNCTYPE(None, POINTER(rq))),
    ('rq_offline', CFUNCTYPE(None, POINTER(rq))),
    ('set_curr_task', CFUNCTYPE(None, POINTER(rq))),
    ('task_tick', CFUNCTYPE(None, POINTER(rq), POINTER(task_struct), c_int)),
    ('task_fork', CFUNCTYPE(None, POINTER(task_struct))),
    ('switched_from', CFUNCTYPE(None, POINTER(rq), POINTER(task_struct), c_int)),
    ('switched_to', CFUNCTYPE(None, POINTER(rq), POINTER(task_struct), c_int)),
    ('prio_changed', CFUNCTYPE(None, POINTER(rq), POINTER(task_struct), c_int, c_int)),
    ('get_rr_interval', CFUNCTYPE(c_uint, POINTER(rq), POINTER(task_struct))),
    ('moved_group', CFUNCTYPE(None, POINTER(task_struct), c_int)),
]
class sched_entity(Structure):
    pass
class load_weight(Structure):
    pass
load_weight._fields_ = [
    ('weight', c_ulong),
    ('inv_weight', c_ulong),
]
class sched_statistics(Structure):
    pass
sched_statistics._pack_ = 4
sched_statistics._fields_ = [
    ('wait_start', u64),
    ('wait_max', u64),
    ('wait_count', u64),
    ('wait_sum', u64),
    ('iowait_count', u64),
    ('iowait_sum', u64),
    ('sleep_start', u64),
    ('sleep_max', u64),
    ('sum_sleep_runtime', s64),
    ('block_start', u64),
    ('block_max', u64),
    ('exec_max', u64),
    ('slice_max', u64),
    ('nr_migrations_cold', u64),
    ('nr_failed_migrations_affine', u64),
    ('nr_failed_migrations_running', u64),
    ('nr_failed_migrations_hot', u64),
    ('nr_forced_migrations', u64),
    ('nr_wakeups', u64),
    ('nr_wakeups_sync', u64),
    ('nr_wakeups_migrate', u64),
    ('nr_wakeups_local', u64),
    ('nr_wakeups_remote', u64),
    ('nr_wakeups_affine', u64),
    ('nr_wakeups_affine_attempts', u64),
    ('nr_wakeups_passive', u64),
    ('nr_wakeups_idle', u64),
]
class cfs_rq(Structure):
    pass
sched_entity._pack_ = 4
sched_entity._fields_ = [
    ('load', load_weight),
    ('run_node', rb_node),
    ('group_node', list_head),
    ('on_rq', c_uint),
    ('exec_start', u64),
    ('sum_exec_runtime', u64),
    ('vruntime', u64),
    ('prev_sum_exec_runtime', u64),
    ('nr_migrations', u64),
    ('statistics', sched_statistics),
    ('parent', POINTER(sched_entity)),
    ('cfs_rq', POINTER(cfs_rq)),
    ('my_q', POINTER(cfs_rq)),
]
class sched_rt_entity(Structure):
    pass
class rt_rq(Structure):
    pass
sched_rt_entity._fields_ = [
    ('run_list', list_head),
    ('timeout', c_ulong),
    ('time_slice', c_uint),
    ('nr_cpus_allowed', c_int),
    ('back', POINTER(sched_rt_entity)),
    ('parent', POINTER(sched_rt_entity)),
    ('rt_rq', POINTER(rt_rq)),
    ('my_q', POINTER(rt_rq)),
]
class hlist_head(Structure):
    pass
class hlist_node(Structure):
    pass
hlist_head._fields_ = [
    ('first', POINTER(hlist_node)),
]
class sched_info(Structure):
    pass
sched_info._pack_ = 4
sched_info._fields_ = [
    ('pcount', c_ulong),
    ('run_delay', c_ulonglong),
    ('last_arrival', c_ulonglong),
    ('last_queued', c_ulonglong),
    ('bkl_count', c_uint),
]
class plist_node(Structure):
    pass
class plist_head(Structure):
    pass
plist_head._fields_ = [
    ('prio_list', list_head),
    ('node_list', list_head),
]
plist_node._fields_ = [
    ('prio', c_int),
    ('plist', plist_head),
]
class mm_struct(Structure):
    pass
class task_rss_stat(Structure):
    pass
task_rss_stat._fields_ = [
    ('events', c_int),
    ('count', c_int * 3),
]
class pid_link(Structure):
    pass
hlist_node._fields_ = [
    ('next', POINTER(hlist_node)),
    ('pprev', POINTER(POINTER(hlist_node))),
]
class pid(Structure):
    pass
pid_link._fields_ = [
    ('node', hlist_node),
    ('pid', POINTER(pid)),
]
class completion(Structure):
    pass
class timespec(Structure):
    pass
timespec._fields_ = [
    ('tv_sec', __kernel_time_t),
    ('tv_nsec', c_long),
]
class task_cputime(Structure):
    pass
task_cputime._pack_ = 4
task_cputime._fields_ = [
    ('utime', cputime_t),
    ('stime', cputime_t),
    ('sum_exec_runtime', c_ulonglong),
]
class cred(Structure):
    pass
class key(Structure):
    pass
class thread_group_cred(Structure):
    pass
class user_struct(Structure):
    pass
class group_info(Structure):
    pass
class rcu_head(Structure):
    pass
rcu_head._fields_ = [
    ('next', POINTER(rcu_head)),
    ('func', CFUNCTYPE(None, POINTER(rcu_head))),
]
cred._fields_ = [
    ('usage', atomic_t),
    ('uid', uid_t),
    ('gid', gid_t),
    ('suid', uid_t),
    ('sgid', gid_t),
    ('euid', uid_t),
    ('egid', gid_t),
    ('fsuid', uid_t),
    ('fsgid', gid_t),
    ('securebits', c_uint),
    ('cap_inheritable', kernel_cap_t),
    ('cap_permitted', kernel_cap_t),
    ('cap_effective', kernel_cap_t),
    ('cap_bset', kernel_cap_t),
    ('jit_keyring', c_ubyte),
    ('thread_keyring', POINTER(key)),
    ('request_key_auth', POINTER(key)),
    ('tgcred', POINTER(thread_group_cred)),
    ('security', c_void_p),
    ('user', POINTER(user_struct)),
    ('group_info', POINTER(group_info)),
    ('rcu', rcu_head),
]
class mutex(Structure):
    pass
class thread_info(Structure):
    pass
mutex._fields_ = [
    ('count', atomic_t),
    ('wait_lock', spinlock_t),
    ('wait_list', list_head),
    ('owner', POINTER(thread_info)),
]
class sysv_sem(Structure):
    pass
class sem_undo_list(Structure):
    pass
sysv_sem._fields_ = [
    ('undo_list', POINTER(sem_undo_list)),
]
class thread_struct(Structure):
    pass
class perf_event(Structure):
    pass
class fpu(Structure):
    pass
class thread_xstate(Union):
    pass
fpu._fields_ = [
    ('state', POINTER(thread_xstate)),
]
class vm86_struct(Structure):
    pass
thread_struct._fields_ = [
    ('tls_array', desc_struct * 3),
    ('sp0', c_ulong),
    ('sp', c_ulong),
    ('sysenter_cs', c_ulong),
    ('ip', c_ulong),
    ('gs', c_ulong),
    ('ptrace_bps', POINTER(perf_event) * 4),
    ('debugreg6', c_ulong),
    ('ptrace_dr7', c_ulong),
    ('cr2', c_ulong),
    ('trap_no', c_ulong),
    ('error_code', c_ulong),
    ('fpu', fpu),
    ('vm86_info', POINTER(vm86_struct)),
    ('screen_bitmap', c_ulong),
    ('v86flags', c_ulong),
    ('v86mask', c_ulong),
    ('saved_sp0', c_ulong),
    ('saved_fs', c_uint),
    ('saved_gs', c_uint),
    ('io_bitmap_ptr', POINTER(c_ulong)),
    ('iopl', c_ulong),
    ('io_bitmap_max', c_uint),
]
class fs_struct(Structure):
    pass
class files_struct(Structure):
    pass
class nsproxy(Structure):
    pass
class signal_struct(Structure):
    pass
class sighand_struct(Structure):
    pass
class sigset_t(Structure):
    pass
sigset_t._fields_ = [
    ('sig', c_ulong * 2),
]
class sigpending(Structure):
    pass
sigpending._fields_ = [
    ('list', list_head),
    ('signal', sigset_t),
]
class audit_context(Structure):
    pass
class seccomp_t(Structure):
    pass
seccomp_t._fields_ = [
    ('mode', c_int),
]
class irqaction(Structure):
    pass
class rt_mutex_waiter(Structure):
    pass
class bio_list(Structure):
    pass
class reclaim_state(Structure):
    pass
class backing_dev_info(Structure):
    pass
class io_context(Structure):
    pass
class task_io_accounting(Structure):
    pass
task_io_accounting._pack_ = 4
task_io_accounting._fields_ = [
    ('rchar', u64),
    ('wchar', u64),
    ('syscr', u64),
    ('syscw', u64),
    ('read_bytes', u64),
    ('write_bytes', u64),
    ('cancelled_write_bytes', u64),
]
class nodemask_t(Structure):
    pass
nodemask_t._fields_ = [
    ('bits', c_ulong * 1),
]
class css_set(Structure):
    pass
class robust_list_head(Structure):
    pass
class futex_pi_state(Structure):
    pass
class perf_event_context(Structure):
    pass
class pipe_inode_info(Structure):
    pass
class task_delay_info(Structure):
    pass
class prop_local_single(Structure):
    pass
prop_local_single._fields_ = [
    ('events', c_ulong),
    ('period', c_ulong),
    ('shift', c_int),
    ('lock', spinlock_t),
]
class latency_record(Structure):
    pass
latency_record._fields_ = [
    ('backtrace', c_ulong * 12),
    ('count', c_uint),
    ('time', c_ulong),
    ('max', c_ulong),
]
class ftrace_ret_stack(Structure):
    pass
class memcg_batch_info(Structure):
    pass
class mem_cgroup(Structure):
    pass
memcg_batch_info._fields_ = [
    ('do_batch', c_int),
    ('memcg', POINTER(mem_cgroup)),
    ('bytes', c_ulong),
    ('memsw_bytes', c_ulong),
]
task_struct._fields_ = [
    ('state', c_long),
    ('stack', c_void_p),
    ('usage', atomic_t),
    ('flags', c_uint),
    ('ptrace', c_uint),
    ('lock_depth', c_int),
    ('prio', c_int),
    ('static_prio', c_int),
    ('normal_prio', c_int),
    ('rt_priority', c_uint),
    ('sched_class', POINTER(sched_class)),
    ('se', sched_entity),
    ('rt', sched_rt_entity),
    ('preempt_notifiers', hlist_head),
    ('fpu_counter', c_ubyte),
    ('btrace_seq', c_uint),
    ('policy', c_uint),
    ('cpus_allowed', cpumask_t),
    ('sched_info', sched_info),
    ('tasks', list_head),
    ('pushable_tasks', plist_node),
    ('mm', POINTER(mm_struct)),
    ('active_mm', POINTER(mm_struct)),
    ('rss_stat', task_rss_stat),
    ('exit_state', c_int),
    ('exit_code', c_int),
    ('exit_signal', c_int),
    ('pdeath_signal', c_int),
    ('personality', c_uint),
    ('did_exec', c_uint, 1),
    ('in_execve', c_uint, 1),
    ('in_iowait', c_uint, 1),
    ('sched_reset_on_fork', c_uint, 1),
    ('pid', pid_t),
    ('tgid', pid_t),
    ('stack_canary', c_ulong),
    ('real_parent', POINTER(task_struct)),
    ('parent', POINTER(task_struct)),
    ('children', list_head),
    ('sibling', list_head),
    ('group_leader', POINTER(task_struct)),
    ('ptraced', list_head),
    ('ptrace_entry', list_head),
    ('pids', pid_link * 3),
    ('thread_group', list_head),
    ('vfork_done', POINTER(completion)),
    ('set_child_tid', POINTER(c_int)),
    ('clear_child_tid', POINTER(c_int)),
    ('utime', cputime_t),
    ('stime', cputime_t),
    ('utimescaled', cputime_t),
    ('stimescaled', cputime_t),
    ('gtime', cputime_t),
    ('prev_utime', cputime_t),
    ('prev_stime', cputime_t),
    ('nvcsw', c_ulong),
    ('nivcsw', c_ulong),
    ('start_time', timespec),
    ('real_start_time', timespec),
    ('min_flt', c_ulong),
    ('maj_flt', c_ulong),
    ('cputime_expires', task_cputime),
    ('cpu_timers', list_head * 3),
    ('real_cred', POINTER(cred)),
    ('cred', POINTER(cred)),
    ('cred_guard_mutex', mutex),
    ('replacement_session_keyring', POINTER(cred)),
    ('comm', c_char * 16),
    ('link_count', c_int),
    ('total_link_count', c_int),
    ('sysvsem', sysv_sem),
    ('last_switch_count', c_ulong),
    ('thread', thread_struct),
    ('fs', POINTER(fs_struct)),
    ('files', POINTER(files_struct)),
    ('nsproxy', POINTER(nsproxy)),
    ('signal', POINTER(signal_struct)),
    ('sighand', POINTER(sighand_struct)),
    ('blocked', sigset_t),
    ('real_blocked', sigset_t),
    ('saved_sigmask', sigset_t),
    ('pending', sigpending),
    ('sas_ss_sp', c_ulong),
    ('sas_ss_size', size_t),
    ('notifier', CFUNCTYPE(c_int, c_void_p)),
    ('notifier_data', c_void_p),
    ('notifier_mask', POINTER(sigset_t)),
    ('audit_context', POINTER(audit_context)),
    ('loginuid', uid_t),
    ('sessionid', c_uint),
    ('seccomp', seccomp_t),
    ('parent_exec_id', u32),
    ('self_exec_id', u32),
    ('alloc_lock', spinlock_t),
    ('irqaction', POINTER(irqaction)),
    ('pi_lock', raw_spinlock_t),
    ('pi_waiters', plist_head),
    ('pi_blocked_on', POINTER(rt_mutex_waiter)),
    ('journal_info', c_void_p),
    ('bio_list', POINTER(bio_list)),
    ('reclaim_state', POINTER(reclaim_state)),
    ('backing_dev_info', POINTER(backing_dev_info)),
    ('io_context', POINTER(io_context)),
    ('ptrace_message', c_ulong),
    ('last_siginfo', POINTER(siginfo_t)),
    ('ioac', task_io_accounting),
    ('acct_rss_mem1', u64),
    ('acct_vm_mem1', u64),
    ('acct_timexpd', cputime_t),
    ('mems_allowed', nodemask_t),
    ('mems_allowed_change_disable', c_int),
    ('cpuset_mem_spread_rotor', c_int),
    ('cpuset_slab_spread_rotor', c_int),
    ('cgroups', POINTER(css_set)),
    ('cg_list', list_head),
    ('robust_list', POINTER(robust_list_head)),
    ('pi_state_list', list_head),
    ('pi_state_cache', POINTER(futex_pi_state)),
    ('perf_event_ctxp', POINTER(perf_event_context)),
    ('perf_event_mutex', mutex),
    ('perf_event_list', list_head),
    ('fs_excl', atomic_t),
    ('rcu', rcu_head),
    ('splice_pipe', POINTER(pipe_inode_info)),
    ('delays', POINTER(task_delay_info)),
    ('dirties', prop_local_single),
    ('latency_record_count', c_int),
    ('latency_record', latency_record * 32),
    ('timer_slack_ns', c_ulong),
    ('default_timer_slack_ns', c_ulong),
    ('scm_work_list', POINTER(list_head)),
    ('curr_ret_stack', c_int),
    ('ret_stack', POINTER(ftrace_ret_stack)),
    ('ftrace_timestamp', c_ulonglong),
    ('trace_overrun', atomic_t),
    ('tracing_graph_pause', atomic_t),
    ('trace', c_ulong),
    ('trace_recursion', c_ulong),
    ('memcg_batch', memcg_batch_info),
]
class vm86_regs(Structure):
    pass
vm86_regs._fields_ = [
    ('ebx', c_long),
    ('ecx', c_long),
    ('edx', c_long),
    ('esi', c_long),
    ('edi', c_long),
    ('ebp', c_long),
    ('eax', c_long),
    ('__null_ds', c_long),
    ('__null_es', c_long),
    ('__null_fs', c_long),
    ('__null_gs', c_long),
    ('orig_eax', c_long),
    ('eip', c_long),
    ('cs', c_ushort),
    ('__csh', c_ushort),
    ('eflags', c_long),
    ('esp', c_long),
    ('ss', c_ushort),
    ('__ssh', c_ushort),
    ('es', c_ushort),
    ('__esh', c_ushort),
    ('ds', c_ushort),
    ('__dsh', c_ushort),
    ('fs', c_ushort),
    ('__fsh', c_ushort),
    ('gs', c_ushort),
    ('__gsh', c_ushort),
]
class revectored_struct(Structure):
    pass
revectored_struct._fields_ = [
    ('__map', c_ulong * 8),
]
vm86_struct._fields_ = [
    ('regs', vm86_regs),
    ('flags', c_ulong),
    ('screen_bitmap', c_ulong),
    ('cpu_type', c_ulong),
    ('int_revectored', revectored_struct),
    ('int21_revectored', revectored_struct),
]
class i387_fsave_struct(Structure):
    pass
i387_fsave_struct._fields_ = [
    ('cwd', u32),
    ('swd', u32),
    ('twd', u32),
    ('fip', u32),
    ('fcs', u32),
    ('foo', u32),
    ('fos', u32),
    ('st_space', u32 * 20),
    ('status', u32),
]
class i387_fxsave_struct(Structure):
    pass
class N18i387_fxsave_struct4DOT_33E(Union):
    pass
class N18i387_fxsave_struct4DOT_334DOT_34E(Structure):
    pass
N18i387_fxsave_struct4DOT_334DOT_34E._pack_ = 4
N18i387_fxsave_struct4DOT_334DOT_34E._fields_ = [
    ('rip', u64),
    ('rdp', u64),
]
class N18i387_fxsave_struct4DOT_334DOT_35E(Structure):
    pass
N18i387_fxsave_struct4DOT_334DOT_35E._fields_ = [
    ('fip', u32),
    ('fcs', u32),
    ('foo', u32),
    ('fos', u32),
]
N18i387_fxsave_struct4DOT_33E._anonymous_ = ['_1', '_0']
N18i387_fxsave_struct4DOT_33E._fields_ = [
    ('_0', N18i387_fxsave_struct4DOT_334DOT_34E),
    ('_1', N18i387_fxsave_struct4DOT_334DOT_35E),
]
class N18i387_fxsave_struct4DOT_36E(Union):
    pass
N18i387_fxsave_struct4DOT_36E._fields_ = [
    ('padding1', u32 * 12),
    ('sw_reserved', u32 * 12),
]
i387_fxsave_struct._anonymous_ = ['_1', '_0']
i387_fxsave_struct._fields_ = [
    ('cwd', u16),
    ('swd', u16),
    ('twd', u16),
    ('fop', u16),
    ('_0', N18i387_fxsave_struct4DOT_33E),
    ('mxcsr', u32),
    ('mxcsr_mask', u32),
    ('st_space', u32 * 32),
    ('xmm_space', u32 * 64),
    ('padding', u32 * 12),
    ('_1', N18i387_fxsave_struct4DOT_36E),
]
class i387_soft_struct(Structure):
    pass
class math_emu_info(Structure):
    pass
i387_soft_struct._fields_ = [
    ('cwd', u32),
    ('swd', u32),
    ('twd', u32),
    ('fip', u32),
    ('fcs', u32),
    ('foo', u32),
    ('fos', u32),
    ('st_space', u32 * 20),
    ('ftop', u8),
    ('changed', u8),
    ('lookahead', u8),
    ('no_update', u8),
    ('rm', u8),
    ('alimit', u8),
    ('info', POINTER(math_emu_info)),
    ('entry_eip', u32),
]
class xsave_struct(Structure):
    pass
class xsave_hdr_struct(Structure):
    pass
xsave_hdr_struct._pack_ = 1
xsave_hdr_struct._fields_ = [
    ('xstate_bv', u64),
    ('reserved1', u64 * 2),
    ('reserved2', u64 * 5),
]
class ymmh_struct(Structure):
    pass
ymmh_struct._fields_ = [
    ('ymmh_space', u32 * 64),
]
xsave_struct._fields_ = [
    ('i387', i387_fxsave_struct),
    ('xsave_hdr', xsave_hdr_struct),
    ('ymmh', ymmh_struct),
]
thread_xstate._fields_ = [
    ('fsave', i387_fsave_struct),
    ('fxsave', i387_fxsave_struct),
    ('soft', i387_soft_struct),
    ('xsave', xsave_struct),
]
perf_event._fields_ = [
]
class exec_domain(Structure):
    pass
class mm_segment_t(Structure):
    pass
mm_segment_t._fields_ = [
    ('seg', c_ulong),
]
class restart_block(Structure):
    pass
class N13restart_block4DOT_11E(Union):
    pass
class N13restart_block4DOT_114DOT_12E(Structure):
    pass
N13restart_block4DOT_114DOT_12E._fields_ = [
    ('arg0', c_ulong),
    ('arg1', c_ulong),
    ('arg2', c_ulong),
    ('arg3', c_ulong),
]
class N13restart_block4DOT_114DOT_13E(Structure):
    pass
N13restart_block4DOT_114DOT_13E._pack_ = 4
N13restart_block4DOT_114DOT_13E._fields_ = [
    ('uaddr', POINTER(u32)),
    ('val', u32),
    ('flags', u32),
    ('bitset', u32),
    ('time', u64),
    ('uaddr2', POINTER(u32)),
]
class N13restart_block4DOT_114DOT_14E(Structure):
    pass
N13restart_block4DOT_114DOT_14E._pack_ = 4
N13restart_block4DOT_114DOT_14E._fields_ = [
    ('index', clockid_t),
    ('rmtp', POINTER(timespec)),
    ('expires', u64),
]
class N13restart_block4DOT_114DOT_15E(Structure):
    pass
class pollfd(Structure):
    pass
N13restart_block4DOT_114DOT_15E._fields_ = [
    ('ufds', POINTER(pollfd)),
    ('nfds', c_int),
    ('has_timeout', c_int),
    ('tv_sec', c_ulong),
    ('tv_nsec', c_ulong),
]
N13restart_block4DOT_11E._anonymous_ = ['_0']
N13restart_block4DOT_11E._fields_ = [
    ('_0', N13restart_block4DOT_114DOT_12E),
    ('futex', N13restart_block4DOT_114DOT_13E),
    ('nanosleep', N13restart_block4DOT_114DOT_14E),
    ('poll', N13restart_block4DOT_114DOT_15E),
]
restart_block._anonymous_ = ['_0']
restart_block._fields_ = [
    ('fn', CFUNCTYPE(c_long, POINTER(restart_block))),
    ('_0', N13restart_block4DOT_11E),
]
thread_info._fields_ = [
    ('task', POINTER(task_struct)),
    ('exec_domain', POINTER(exec_domain)),
    ('flags', __u32),
    ('status', __u32),
    ('cpu', __u32),
    ('preempt_count', c_int),
    ('addr_limit', mm_segment_t),
    ('restart_block', restart_block),
    ('sysenter_return', c_void_p),
    ('previous_esp', c_ulong),
    ('supervisor_stack', __u8 * 0),
    ('uaccess_err', c_int),
]
completion._fields_ = [
    ('done', c_uint),
    ('wait', wait_queue_head_t),
]
class vm_area_struct(Structure):
    pass
class rb_root(Structure):
    pass
rb_root._fields_ = [
    ('rb_node', POINTER(rb_node)),
]
class file(Structure):
    pass
class pgd_t(Structure):
    pass
class rw_semaphore(Structure):
    pass
rw_semaphore._fields_ = [
    ('count', rwsem_count_t),
    ('wait_lock', spinlock_t),
    ('wait_list', list_head),
]
class mm_rss_stat(Structure):
    pass
mm_rss_stat._fields_ = [
    ('count', atomic_long_t * 3),
]
class linux_binfmt(Structure):
    pass
class mm_context_t(Structure):
    pass
mm_context_t._fields_ = [
    ('ldt', c_void_p),
    ('size', c_int),
    ('lock', mutex),
    ('vdso', c_void_p),
    ('user_cs', desc_struct),
    ('exec_limit', c_ulong),
]
class core_state(Structure):
    pass
class mmu_notifier_mm(Structure):
    pass
mm_struct._fields_ = [
    ('mmap', POINTER(vm_area_struct)),
    ('mm_rb', rb_root),
    ('mmap_cache', POINTER(vm_area_struct)),
    ('get_unmapped_area', CFUNCTYPE(c_ulong, POINTER(file), c_ulong, c_ulong, c_ulong, c_ulong)),
    ('get_unmapped_exec_area', CFUNCTYPE(c_ulong, POINTER(file), c_ulong, c_ulong, c_ulong, c_ulong)),
    ('unmap_area', CFUNCTYPE(None, POINTER(mm_struct), c_ulong)),
    ('mmap_base', c_ulong),
    ('task_size', c_ulong),
    ('cached_hole_size', c_ulong),
    ('free_area_cache', c_ulong),
    ('pgd', POINTER(pgd_t)),
    ('mm_users', atomic_t),
    ('mm_count', atomic_t),
    ('map_count', c_int),
    ('mmap_sem', rw_semaphore),
    ('page_table_lock', spinlock_t),
    ('mmlist', list_head),
    ('hiwater_rss', c_ulong),
    ('hiwater_vm', c_ulong),
    ('total_vm', c_ulong),
    ('locked_vm', c_ulong),
    ('shared_vm', c_ulong),
    ('exec_vm', c_ulong),
    ('stack_vm', c_ulong),
    ('reserved_vm', c_ulong),
    ('def_flags', c_ulong),
    ('nr_ptes', c_ulong),
    ('start_code', c_ulong),
    ('end_code', c_ulong),
    ('start_data', c_ulong),
    ('end_data', c_ulong),
    ('start_brk', c_ulong),
    ('brk', c_ulong),
    ('start_stack', c_ulong),
    ('arg_start', c_ulong),
    ('arg_end', c_ulong),
    ('env_start', c_ulong),
    ('env_end', c_ulong),
    ('saved_auxv', c_ulong * 44),
    ('rss_stat', mm_rss_stat),
    ('binfmt', POINTER(linux_binfmt)),
    ('cpu_vm_mask', cpumask_t),
    ('context', mm_context_t),
    ('faultstamp', c_uint),
    ('token_priority', c_uint),
    ('last_interval', c_uint),
    ('flags', c_ulong),
    ('core_state', POINTER(core_state)),
    ('ioctx_lock', spinlock_t),
    ('ioctx_list', hlist_head),
    ('owner', POINTER(task_struct)),
    ('exe_file', POINTER(file)),
    ('num_exe_file_vmas', c_ulong),
    ('mmu_notifier_mm', POINTER(mmu_notifier_mm)),
]
sem_undo_list._fields_ = [
    ('refcnt', atomic_t),
    ('lock', spinlock_t),
    ('list_proc', list_head),
]
class upid(Structure):
    pass
class pid_namespace(Structure):
    pass
upid._fields_ = [
    ('nr', c_int),
    ('ns', POINTER(pid_namespace)),
    ('pid_chain', hlist_node),
]
pid._fields_ = [
    ('count', atomic_t),
    ('level', c_uint),
    ('tasks', hlist_head * 3),
    ('rcu', rcu_head),
    ('numbers', upid * 1),
]
rt_mutex_waiter._fields_ = [
]
nsproxy._fields_ = [
]
class key_type(Structure):
    pass
class key_user(Structure):
    pass
class N3key5DOT_189E(Union):
    pass
N3key5DOT_189E._fields_ = [
    ('expiry', time_t),
    ('revoked_at', time_t),
]
class N3key5DOT_190E(Union):
    pass
N3key5DOT_190E._fields_ = [
    ('link', list_head),
    ('x', c_ulong * 2),
    ('p', c_void_p * 2),
]
class N3key5DOT_191E(Union):
    pass
class keyring_list(Structure):
    pass
N3key5DOT_191E._fields_ = [
    ('value', c_ulong),
    ('data', c_void_p),
    ('subscriptions', POINTER(keyring_list)),
]
key._anonymous_ = ['_0']
key._fields_ = [
    ('usage', atomic_t),
    ('serial', key_serial_t),
    ('serial_node', rb_node),
    ('type', POINTER(key_type)),
    ('sem', rw_semaphore),
    ('user', POINTER(key_user)),
    ('security', c_void_p),
    ('_0', N3key5DOT_189E),
    ('uid', uid_t),
    ('gid', gid_t),
    ('perm', key_perm_t),
    ('quotalen', c_ushort),
    ('datalen', c_ushort),
    ('flags', c_ulong),
    ('description', STRING),
    ('type_data', N3key5DOT_190E),
    ('payload', N3key5DOT_191E),
]
audit_context._fields_ = [
]
group_info._fields_ = [
    ('usage', atomic_t),
    ('ngroups', c_int),
    ('nblocks', c_int),
    ('small_block', gid_t * 32),
    ('blocks', POINTER(gid_t) * 0),
]
thread_group_cred._fields_ = [
    ('usage', atomic_t),
    ('tgid', pid_t),
    ('lock', spinlock_t),
    ('session_keyring', POINTER(key)),
    ('process_keyring', POINTER(key)),
    ('rcu', rcu_head),
]
futex_pi_state._fields_ = [
]
robust_list_head._fields_ = [
]
bio_list._fields_ = [
]
fs_struct._fields_ = [
]
perf_event_context._fields_ = [
]
cfs_rq._fields_ = [
]
class k_sigaction(Structure):
    pass
class sigaction(Structure):
    pass
sigaction._fields_ = [
    ('sa_handler', __sighandler_t),
    ('sa_flags', c_ulong),
    ('sa_restorer', __sigrestore_t),
    ('sa_mask', sigset_t),
]
k_sigaction._fields_ = [
    ('sa', sigaction),
]
sighand_struct._fields_ = [
    ('count', atomic_t),
    ('action', k_sigaction * 64),
    ('siglock', spinlock_t),
    ('signalfd_wqh', wait_queue_head_t),
]
class hrtimer(Structure):
    pass

# values for enumeration 'hrtimer_restart'
HRTIMER_NORESTART = 0
HRTIMER_RESTART = 1
hrtimer_restart = c_int # enum
class hrtimer_clock_base(Structure):
    pass
hrtimer._fields_ = [
    ('node', rb_node),
    ('_expires', ktime_t),
    ('_softexpires', ktime_t),
    ('function', CFUNCTYPE(hrtimer_restart, POINTER(hrtimer))),
    ('base', POINTER(hrtimer_clock_base)),
    ('state', c_ulong),
    ('start_pid', c_int),
    ('start_site', c_void_p),
    ('start_comm', c_char * 16),
]
class cpu_itimer(Structure):
    pass
cpu_itimer._fields_ = [
    ('expires', cputime_t),
    ('incr', cputime_t),
    ('error', u32),
    ('incr_error', u32),
]
class thread_group_cputimer(Structure):
    pass
thread_group_cputimer._fields_ = [
    ('cputime', task_cputime),
    ('running', c_int),
    ('lock', spinlock_t),
]
class tty_struct(Structure):
    pass
class rlimit(Structure):
    pass
rlimit._fields_ = [
    ('rlim_cur', c_ulong),
    ('rlim_max', c_ulong),
]
class pacct_struct(Structure):
    pass
pacct_struct._fields_ = [
    ('ac_flag', c_int),
    ('ac_exitcode', c_long),
    ('ac_mem', c_ulong),
    ('ac_utime', cputime_t),
    ('ac_stime', cputime_t),
    ('ac_minflt', c_ulong),
    ('ac_majflt', c_ulong),
]
class taskstats(Structure):
    pass
class tty_audit_buf(Structure):
    pass
signal_struct._pack_ = 4
signal_struct._fields_ = [
    ('sigcnt', atomic_t),
    ('live', atomic_t),
    ('nr_threads', c_int),
    ('wait_chldexit', wait_queue_head_t),
    ('curr_target', POINTER(task_struct)),
    ('shared_pending', sigpending),
    ('group_exit_code', c_int),
    ('notify_count', c_int),
    ('group_exit_task', POINTER(task_struct)),
    ('group_stop_count', c_int),
    ('flags', c_uint),
    ('posix_timers', list_head),
    ('real_timer', hrtimer),
    ('leader_pid', POINTER(pid)),
    ('it_real_incr', ktime_t),
    ('it', cpu_itimer * 2),
    ('cputimer', thread_group_cputimer),
    ('cputime_expires', task_cputime),
    ('cpu_timers', list_head * 3),
    ('tty_old_pgrp', POINTER(pid)),
    ('leader', c_int),
    ('tty', POINTER(tty_struct)),
    ('utime', cputime_t),
    ('stime', cputime_t),
    ('cutime', cputime_t),
    ('cstime', cputime_t),
    ('gtime', cputime_t),
    ('cgtime', cputime_t),
    ('prev_utime', cputime_t),
    ('prev_stime', cputime_t),
    ('nvcsw', c_ulong),
    ('nivcsw', c_ulong),
    ('cnvcsw', c_ulong),
    ('cnivcsw', c_ulong),
    ('min_flt', c_ulong),
    ('maj_flt', c_ulong),
    ('cmin_flt', c_ulong),
    ('cmaj_flt', c_ulong),
    ('inblock', c_ulong),
    ('oublock', c_ulong),
    ('cinblock', c_ulong),
    ('coublock', c_ulong),
    ('maxrss', c_ulong),
    ('cmaxrss', c_ulong),
    ('ioac', task_io_accounting),
    ('sum_sched_runtime', c_ulonglong),
    ('rlim', rlimit * 16),
    ('pacct', pacct_struct),
    ('stats', POINTER(taskstats)),
    ('audit_tty', c_uint),
    ('tty_audit_buf', POINTER(tty_audit_buf)),
    ('oom_adj', c_int),
]
class user_namespace(Structure):
    pass
user_struct._fields_ = [
    ('__count', atomic_t),
    ('processes', atomic_t),
    ('files', atomic_t),
    ('sigpending', atomic_t),
    ('inotify_watches', atomic_t),
    ('inotify_devs', atomic_t),
    ('epoll_watches', atomic_t),
    ('mq_bytes', c_ulong),
    ('locked_shm', c_ulong),
    ('uid_keyring', POINTER(key)),
    ('session_keyring', POINTER(key)),
    ('uidhash_node', hlist_node),
    ('uid', uid_t),
    ('user_ns', POINTER(user_namespace)),
    ('locked_vm', atomic_long_t),
]
backing_dev_info._fields_ = [
]
reclaim_state._fields_ = [
]
task_delay_info._pack_ = 4
task_delay_info._fields_ = [
    ('lock', spinlock_t),
    ('flags', c_uint),
    ('blkio_start', timespec),
    ('blkio_end', timespec),
    ('blkio_delay', u64),
    ('swapin_delay', u64),
    ('blkio_count', u32),
    ('swapin_count', u32),
    ('freepages_start', timespec),
    ('freepages_end', timespec),
    ('freepages_delay', u64),
    ('freepages_count', u32),
]
io_context._fields_ = [
]
pipe_inode_info._fields_ = [
]
rq._fields_ = [
]
rt_rq._fields_ = [
]
files_struct._fields_ = [
]
irqaction._fields_ = [
]
css_set._fields_ = [
]
ftrace_ret_stack._fields_ = [
]
mem_cgroup._fields_ = [
]
pollfd._fields_ = [
]
class N13math_emu_info4DOT_16E(Union):
    pass
class kernel_vm86_regs(Structure):
    pass
N13math_emu_info4DOT_16E._fields_ = [
    ('regs', POINTER(pt_regs)),
    ('vm86', POINTER(kernel_vm86_regs)),
]
math_emu_info._anonymous_ = ['_0']
math_emu_info._fields_ = [
    ('___orig_eip', c_long),
    ('_0', N13math_emu_info4DOT_16E),
]
pgd_t._pack_ = 4
pgd_t._fields_ = [
    ('pgd', pgdval_t),
]
file._fields_ = [
]
class map_segment(Structure):
    pass
class module(Structure):
    pass
exec_domain._fields_ = [
    ('name', STRING),
    ('handler', handler_t),
    ('pers_low', c_ubyte),
    ('pers_high', c_ubyte),
    ('signal_map', POINTER(c_ulong)),
    ('signal_invmap', POINTER(c_ulong)),
    ('err_map', POINTER(map_segment)),
    ('socktype_map', POINTER(map_segment)),
    ('sockopt_map', POINTER(map_segment)),
    ('af_map', POINTER(map_segment)),
    ('module', POINTER(module)),
    ('next', POINTER(exec_domain)),
]
class N14vm_area_struct4DOT_50E(Union):
    pass
class N14vm_area_struct4DOT_504DOT_51E(Structure):
    pass
N14vm_area_struct4DOT_504DOT_51E._fields_ = [
    ('list', list_head),
    ('parent', c_void_p),
    ('head', POINTER(vm_area_struct)),
]
class raw_prio_tree_node(Structure):
    pass
class prio_tree_node(Structure):
    pass
raw_prio_tree_node._fields_ = [
    ('left', POINTER(prio_tree_node)),
    ('right', POINTER(prio_tree_node)),
    ('parent', POINTER(prio_tree_node)),
]
N14vm_area_struct4DOT_50E._fields_ = [
    ('vm_set', N14vm_area_struct4DOT_504DOT_51E),
    ('prio_tree_node', raw_prio_tree_node),
]
class anon_vma(Structure):
    pass
class vm_operations_struct(Structure):
    pass
vm_operations_struct._fields_ = [
]
vm_area_struct._fields_ = [
    ('vm_mm', POINTER(mm_struct)),
    ('vm_start', c_ulong),
    ('vm_end', c_ulong),
    ('vm_next', POINTER(vm_area_struct)),
    ('vm_prev', POINTER(vm_area_struct)),
    ('vm_page_prot', pgprot_t),
    ('vm_flags', c_ulong),
    ('vm_rb', rb_node),
    ('shared', N14vm_area_struct4DOT_50E),
    ('anon_vma_chain', list_head),
    ('anon_vma', POINTER(anon_vma)),
    ('vm_ops', POINTER(vm_operations_struct)),
    ('vm_pgoff', c_ulong),
    ('vm_file', POINTER(file)),
    ('vm_private_data', c_void_p),
    ('vm_truncate_count', c_ulong),
]
class core_thread(Structure):
    pass
core_thread._fields_ = [
    ('task', POINTER(task_struct)),
    ('next', POINTER(core_thread)),
]
core_state._fields_ = [
    ('nr_threads', atomic_t),
    ('dumper', core_thread),
    ('startup', completion),
]
linux_binfmt._fields_ = [
]
mmu_notifier_mm._fields_ = [
]
pid_namespace._fields_ = [
]
class hrtimer_cpu_base(Structure):
    pass
hrtimer_clock_base._fields_ = [
    ('cpu_base', POINTER(hrtimer_cpu_base)),
    ('index', clockid_t),
    ('active', rb_root),
    ('first', POINTER(rb_node)),
    ('resolution', ktime_t),
    ('get_time', CFUNCTYPE(ktime_t)),
    ('softirq_time', ktime_t),
    ('offset', ktime_t),
]
key_type._fields_ = [
]
keyring_list._fields_ = [
]
key_user._fields_ = [
]
user_namespace._fields_ = [
]
tty_struct._fields_ = [
]
taskstats._fields_ = [
]
tty_audit_buf._fields_ = [
]
module._fields_ = [
]
kernel_vm86_regs._fields_ = [
    ('pt', pt_regs),
    ('es', c_ushort),
    ('__esh', c_ushort),
    ('ds', c_ushort),
    ('__dsh', c_ushort),
    ('fs', c_ushort),
    ('__fsh', c_ushort),
    ('gs', c_ushort),
    ('__gsh', c_ushort),
]
map_segment._fields_ = [
]
prio_tree_node._fields_ = [
    ('left', POINTER(prio_tree_node)),
    ('right', POINTER(prio_tree_node)),
    ('parent', POINTER(prio_tree_node)),
    ('start', c_ulong),
    ('last', c_ulong),
]
anon_vma._fields_ = [
]
hrtimer_cpu_base._fields_ = [
    ('lock', raw_spinlock_t),
    ('clock_base', hrtimer_clock_base * 2),
    ('expires_next', ktime_t),
    ('hres_active', c_int),
    ('hang_detected', c_int),
    ('nr_events', c_ulong),
    ('nr_retries', c_ulong),
    ('nr_hangs', c_ulong),
    ('max_hang_time', ktime_t),
]
__all__ = ['__kernel_uid32_t', 'wait_queue_t', 'page_cgroup',
           'kmem_cache', 'N18i387_fxsave_struct4DOT_33E', '__s8',
           'sigval_t', 'uint8_t', '__sum16', '__kernel_size_t',
           '__s16', '__kernel_daddr_t', '__le64', 'mmu_notifier_mm',
           'cpumask_var_t', 'mqd_t', 'umode_t', 'pcpu_fc_free_fn_t',
           'tty_audit_buf', 'linux_binfmt', 'hrtimer_clock_base',
           'HRTIMER_NORESTART', 'timer_t', '__wait_queue',
           'task_cputime', 'thread_struct', 'timespec', '__le16',
           'hlist_head', 'N8spinlock4DOT_40E', 'raw_spinlock_t',
           'zoneref', 'N13restart_block4DOT_11E', 'u32',
           'work_struct', 'va_list', 'group_info', 'vm_area_struct',
           's16', 'kernel_cap_t', 'taskstats', 'pgd_t', 'zone',
           '__kernel_sighandler_t', 'user_struct',
           'N13restart_block4DOT_114DOT_14E', 'sighand_struct',
           'N7siginfo5DOT_1245DOT_128E', 'key_type',
           'memcg_batch_info', '__kernel_old_uid_t', 'zone_padding',
           'sched_statistics', 'daddr_t', '__kernel_uid16_t', '__u32',
           'hlist_node', 'pglist_data', '__kernel_gid16_t', 'pid_t',
           '__kernel_loff_t', 'pgprot', 'ftrace_ret_stack',
           'handler_t', 'rb_augment_f', 'N4page4DOT_474DOT_48E',
           'u_int8_t', 'u64', 'off_t',
           'N11desc_struct4DOT_244DOT_25E', 's8', 'fpu', 'cpumask',
           'i387_fxsave_struct', 'wait_queue_func_t', 'nsproxy',
           'signal_struct', '__kernel_gid_t', 'key_t',
           'per_cpu_pages', 'uint', 'rwsem_count_t',
           'N18i387_fxsave_struct4DOT_334DOT_35E', 's64',
           'apm_eventinfo_t', '__sighandler_t',
           'N18i387_fxsave_struct4DOT_36E', 'pg_data_t',
           'atomic_long_t', 'ssize_t', 'key_perm_t', '__kernel_pid_t',
           'size_t', 'rb_node', 'pudval_t', 'sigval', 'exec_domain',
           'dma_addr_t', 'uid16_t', 'zonelist_cache', 'key_ref_t',
           'cred', 'upid', 'u_char', '__wsum', 'atomic_t', 'uid_t',
           'N13restart_block4DOT_114DOT_12E', 'u_int64_t',
           'u_int16_t', 'old_uid_t', 'spinlock', 'fmode_t',
           'plist_node', 'sigset_t', 'pgprot_t', '__be64',
           'plist_head', 'restart_block', '__kernel_fd_set',
           'sigevent', 'clock_t', 'hrtimer', 'rq',
           'N7siginfo5DOT_124E', 'xsave_hdr_struct', 'arch_spinlock',
           'u_int32_t', 'hrtimer_restart',
           'N7siginfo5DOT_1245DOT_125E', '__gnuc_va_list', 'sector_t',
           'ktime_t', 'thread_xstate', 'sched_class', 'ctor_fn_t',
           'ino_t', '__kernel_uid_t', 'cpu_itimer', 'fs_struct',
           'old_gid_t', 'cap_user_header_t', 'pgdval_t', 'sigpending',
           'stack_t', '__kernel_clockid_t', 'raw_spinlock',
           'cap_user_data_t', '__be16', 's32', 'i387_soft_struct',
           'spinlock_t', 'N3key5DOT_191E', 'N4page4DOT_45E',
           'uint64_t', 'dma64_addr_t', '__kernel_ptrdiff_t',
           '__kernel_ipc_pid_t',
           'N18i387_fxsave_struct4DOT_334DOT_34E',
           'perf_event_context', 'nlink_t', '__u8',
           'pcpu_fc_cpu_distance_fn_t', '__s32', 'xsave_struct',
           'N7siginfo5DOT_1245DOT_129E', 'uint32_t', 'ulong',
           'ymmh_struct', 'sigevent_t', 'N13math_emu_info4DOT_16E',
           'int8_t', 'pacct_struct', 'revectored_struct', 'anon_vma',
           'rb_root', 'pipe_inode_info', 'dev_t', 'gfp_t',
           'N4page4DOT_454DOT_46E', 'reclaim_state', 'N4page4DOT_49E',
           'ktime', '__kernel_dev_t', 'gid16_t', 'mode_t',
           'N13restart_block4DOT_114DOT_13E', 'completion', 'gid_t',
           'N8sigevent5DOT_1315DOT_132E', '__kernel_mode_t',
           'siginfo', 'exitcall_t', '__kernel_old_dev_t',
           'mem_cgroup', 'tty_struct', 'irqaction', 'seqcount',
           'N3key5DOT_189E', 'backing_dev_info', '__s64',
           'N7siginfo5DOT_1245DOT_126E', 'module', 'aio_context_t',
           'mm_rss_stat', 'int16_t', 'N7siginfo5DOT_1245DOT_130E',
           'siginfo_t', 'map_segment', '__kernel_gid32_t',
           'wait_queue_head_t', 'address_space', 'mutex',
           'sigaltstack', 'key_serial_t', 'physid_mask_t',
           'mm_segment_t', 'zone_lru', 'task_delay_info', '__u16',
           '__kernel_nlink_t', 'tss_desc', 'user_namespace',
           'sigaction', 'task_rss_stat', 'initcall_t', 'ushort',
           'clockid_t', 'ldt_desc', 'caddr_t', 'uint16_t',
           '__kernel_mqd_t', 'prio_tree_node', 'key', 'int32_t',
           '__le32', 'latency_record', 'blkcnt_t',
           'thread_group_cputimer', 'N3key5DOT_190E', 'ctl_table',
           'key_user', 'u16', 'k_sigaction', 'perf_event',
           'pm_message', 'pollfd', 'raw_prio_tree_node',
           'physid_mask', 'u_long', 'nodemask_t', 'pm_message_t',
           'int64_t', 'sched_rt_entity', 'pt_regs', 'time_t',
           'u_short', 'hrtimer_cpu_base', 'cputime_t', 'bio_list',
           'desc_struct', 'io_context', 'rw_semaphore', 'sched_info',
           '__kernel_off_t', 'phys_addr_t', '__u64', 'seccomp_t',
           '__user_cap_header_struct', 'futex_pi_state',
           'core_thread', 'suseconds_t', 'zonelist',
           'HRTIMER_RESTART', 'pid_link', '__kernel_ino_t',
           'sem_undo_list', 'fd_set', 'kernel_vm86_regs', 'pteval_t',
           '__user_cap_data_struct', 'loff_t', '__kernel_time_t',
           'cpumask_t', 'seqcount_t', '__sigrestore_t', 'thread_info',
           'page', 'old_sigset_t', 'rt_rq', '__kernel_ssize_t',
           '__kernel_suseconds_t', 'resource_size_t', 'list_head',
           'sched_entity', 'gate_desc', '__restorefn_t',
           '__kernel_caddr_t', 'N14vm_area_struct4DOT_504DOT_51E',
           '__key_reference_with_attributes', 'pmdval_t', 'rcu_head',
           'audit_context', '__kernel_clock_t', 'kernel_cap_struct',
           'sysv_sem', 'N11desc_struct4DOT_244DOT_26E',
           '__signalfn_t', 'cycles_t', '__be32', 'core_state',
           'keyring_list', 'free_area', 'prop_local_single',
           'zone_reclaim_stat', 'arch_spinlock_t',
           'N13restart_block4DOT_114DOT_15E', '__wait_queue_head',
           'ptrdiff_t', '__kernel_key_t', 'css_set', 'load_weight',
           'vm86_regs', 'apm_event_t', 'task_struct', 'u8', 'rlimit',
           'uintptr_t', 'N7siginfo5DOT_1245DOT_127E', 'u_int',
           'mm_context_t', 'i387_fsave_struct', 'task_io_accounting',
           'pgtable_t', '__kernel_old_gid_t', 'unchar',
           'pcpu_fc_populate_pte_fn_t', 'cfs_rq', 'N4page4DOT_47E',
           'pid', 'file', 'mm_struct', 'pcpu_fc_alloc_fn_t',
           'N11desc_struct4DOT_24E', '__kernel_timer_t',
           'N8sigevent5DOT_131E', 'math_emu_info', 'cputime64_t',
           'N14vm_area_struct4DOT_50E', 'pgprotval_t', 'work_func_t',
           'robust_list_head', 'per_cpu_pageset',
           'vm_operations_struct', 'thread_group_cred',
           'files_struct', 'vm86_struct', 'pid_namespace',
           'rt_mutex_waiter']
