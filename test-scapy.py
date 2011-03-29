
import scapy.config 

class a:
  def __init__(self):
    scapy.config.conf.use_pcap=True
    self.packetCount = 10
    self.timeout = 10
    self.filterRules = 'tcp and port 22'    
    return
  def enqueue(self,p):
    print len(p), p['TCP'].seq, p.summary()
  def run(self):
    from scapy.all import sniff
    print ('Using L2listen = %s'%(scapy.config.conf.L2listen)) 
    sniff(iface='any', count=self.packetCount,timeout=self.timeout,store=0,filter=self.filterRules,prn=self.enqueue)
    print ('============ SNIFF Terminated ====================')


o=a()

o.run()

