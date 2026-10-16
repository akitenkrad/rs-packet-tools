import sys, time
from scapy.all import PcapReader, RawPcapReader, IP, TCP, UDP, conf
path, n = sys.argv[1], int(sys.argv[2])
print("TCP payload_guess entries:", len(TCP.payload_guess), " UDP:", len(UDP.payload_guess), " layers:", len(conf.layers))
t=time.perf_counter(); c=0
for rec in RawPcapReader(path):
    c+=1
    if c>=n: break
t1=time.perf_counter()-t; print(f"raw read      : {c} pkts {t1:.2f}s {c/t1:,.0f} pkt/s")
t=time.perf_counter(); c=0; flows={}
for p in PcapReader(path):
    c+=1
    if IP in p:
        ip=p[IP]; l4=ip.payload
        k=(ip.src,ip.dst,ip.proto,getattr(l4,'sport',0),getattr(l4,'dport',0))
        flows[k]=flows.get(k,0)+len(p)
    if c>=n: break
t2=time.perf_counter()-t; print(f"full dissect+5tuple: {c} pkts {t2:.2f}s {c/t2:,.0f} pkt/s  flows={len(flows)}")
