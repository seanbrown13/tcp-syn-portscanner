#!/usr/bin/python
import sys
from random import randint
from scapy.all import IP,TCP,sr1
from ipaddress import IPv4Network

sip = unicode(sys.argv[1]) # IP or IP range
t = int(sys.argv[4]) # Timeout setting
v = int(sys.argv[5]) # Verbosity setting

def spkt(host):
    stport = int(sys.argv[2]) # Start port
    enport = int(sys.argv[3]) # End port
    # Template for tcp sending. tcps = final packet sent (list), 
    template = IP(dst=str(host))/TCP(sport=randint(1,65535),flags='S') # Setup constant values, leaving destination IP and port out so that they can be passed in by the user
    tcps = [] 
    stport
    
    for pkt in range(0,enport): # Loop through all the packets. pkt is the current packet
        for stport in range(stport,enport): # Loop through all the ports. stport is the start port and will be incremented as far as the user specifies
            print stport,"of",enport,"for this host"
            tcps.extend(template) # Firstly fill in the list with the constant values
            tcps[pkt].dport = stport # Secondly fill in the destination port each time
            print "Sending TCP packet to",tcps[pkt].dst,"on port",tcps[pkt].dport
            tcpr = sr1(tcps[pkt],timeout=t,verbose=v) # Send packet and capture response 

            if tcpr is None: # No response
                print "Port",stport,"is filtered"
            elif(tcpr[TCP].flags == 0x12): # SYN-ACK
                print "Port",stport,"is open"
            elif(tcpr[TCP].flags == 0x14): # RST
                print "Port",stport,"is closed"
        stport += 1 

# If an IP range is specified, identify input as such and make list of addresses using ipv4network
for i in range(0,len(sip)):
    if (sip[i] == "/"):
        sips = IPv4Network(sip)
        for host in sips: # Feed each of these IP's in one by one to spkt so appropriate ports can be probed
            spkt(host)
            
    elif(sip[i] != "/"): # Loop through all characters of IP to see if a range is specified
        i+=1
        if(i==len(sip)): # Single IP addresses will not have '/' characters at any point 
            host=sip
            spkt(host) # Therefore, such IPs can be passed straight into our packet creator function
        else: 
            continue 
# End when all IP/Ports scanned.
