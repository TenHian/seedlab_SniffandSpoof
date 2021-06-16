#!/usr/bin/python3
from scapy.all import *
import json


def spoof(pkt):
    pkt.show()

    a=Ether()
    a.src=pkt[Ether].dst
    a.dst=pkt[Ether].src
    a.type=pkt[Ether].type

    b=IP()
    b.version=pkt[IP].version
    b.ihl=pkt[IP].ihl
    b.tos=pkt[IP].tos
    b.len=pkt[IP].len
    b.id=pkt[IP].id
    b.ttl=128
    # b.chksum=0
    b.src=pkt[IP].dst #scr是源，dst是目的IP，将其互换，就变成了reply
    b.dst=pkt[IP].src #伪装成dst
    
    c=ICMP()
    c.type="echo-reply" #将类型换成echo reply
    c.code=0
    c.chksum=0
    c.id=pkt[ICMP].id
    c.seq=pkt[ICMP].seq

    d=pkt[Raw].load

    p=a/b/c/d
    #p.show()

    s=Ether(p)

    s.show()

    sendp(s)

pkt=sniff(iface='ens33',filter='icmp[icmptype]==icmp-echo && host 192.168.52.129',prn=spoof)#嗅探icmp request
sniff_spoof(pkt)