#!/usr/bin/env python3

from scapy.all import *
def print_pkt(pkt):
	pkt.show() 

pkt = sniff(iface='ens33', filter='net 10.193.255.0/24', prn=print_pkt)

print_pkt(pkt)