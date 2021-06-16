#!/usr/bin/env python3

from scapy.all import *

for i in range(0,4):
	a=IP()
	a.dst='192.168.52.129'
	b=ICMP()
	c=a/b
	send(c)