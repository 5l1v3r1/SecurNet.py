#!/usr/bin/python

#I LOVE PYTHON :) 

from scapy.layers.l2 import ARP,Ether,sniff

db = {}

def security(pkt):
	if ARP in pkt:
		ip,mac = pkt[ARP].psrc , pkt[ARP].hwsrc
		if ip in db:
			if mac != db[ip]:
				if Ether in pkt:
					target = pkt[Ether].dst
				else:
					target = "%s?" % pkt[ARP].pdst
				return "[!]:Worning! :>> Poisoning Attack: Target: %s | Victem: %s | Attacker: %s " %(target,ip,mac)
		else:
			db[ip] = mac
			return "[!]Warning :>> SomeOne Is Trying To Gathering info from Router: | %s | %s "%(mac,ip)


sniff(store=0,prn=security)

