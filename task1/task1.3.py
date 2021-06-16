#!/usr/bin/env python3

from scapy.all import *

final=0
ttl=1
a=IP()
a.dst='192.168.52.1' #目的IP
b=ICMP()

while final==False:
	a.ttl=ttl
	ans,unas=sr(a/b)
	print(ans.summary())

	if ans.res[0][1].type==0:
		final=True
	else:
		ttl+=1

print("到%s的距离为%d"%(a.dst,ttl))