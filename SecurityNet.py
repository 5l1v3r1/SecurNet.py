#!/usr/bin/python

#I LOVE PYTHON :) 
## Checking NetWork From ARP POISONING AND INFORMATION GATHERING ATTACKS Using Scapy Library
## By: Oseid Aldary

## START :)
try:
 from scapy.layers.l2 import ARP,Ether,sniff
except:
	print("[!] Error The [Scapy] Library Is Not Installed On Your Pc !")
	exit(1)
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
				return "[!]:Worning! :>> Poisoning Attack: Target: {} | Victem: {} | Attacker: {} ".format(target,ip,mac)
		else:
			db[ip] = mac
			return "[!]Warning :>> SomeOne Is Trying To Gathering info from Router: | {} | {} ".format(mac,ip)
# Start Checking ... :)

print("\n[#] Checking NetWork Start [#]\n")
sniff(store=0,prn=security)
#Done! :)

##############################################################
##################### 		     #########################
#####################  END OF SCRIPT #########################
#####################                #########################
##############################################################
#This SCRIPT by Oseid Aldary
#Have a nice day :)
#GoodBye
