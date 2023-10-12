from scapy import *
from scapy.data import TCP_SERVICES
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sr1

# TCP_REVERSE = dict((k, TCP_SERVICES[k]) for k in TCP_SERVICES.keys())
# print(TCP_REVERSE)

p = IP(dst='e1.ru') / UDP(dport=80)
print(p.show(), '\n\n')
# print(p[UDP].ack)
