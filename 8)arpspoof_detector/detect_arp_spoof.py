#!/usr/bin/env python

import scapy.all as scapy
import optparse



def get_arguements():
    # Parse the arguements from command line
    parser = optparse.OptionParser()                                             
    parser.add_option("-i", "--interface", dest="interface", help="Interface")     
    options=parser.parse_args() [0]                                              

    # checks all the necessary options are provided 
    if not options.interface:
        parser.error("[-]Please specify the interface,use --help for more info")

    return options

def get_mac(ip,interface):
    arp_request=scapy.ARP(pdst=ip)                                               #for creating arp packet
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")                               #for creating broadcast packet
    arp_request_broadcast=broadcast/arp_request                                  #appending both packets
    answered_list=scapy.srp(arp_request_broadcast,timeout=1,iface=interface,verbose=False) [0]

    return answered_list[0][1].hwsrc


def process_sniffed_packet(packet):                                          #filtering the packet
    # Detects the arp response packet on our interface
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op==2:
        try:
            real_mac=get_mac(packet[scapy.ARP].psrc,options.interface)
            response_mac= packet[scapy.ARP].hwsrc
 
            if real_mac!=response_mac:
                global pos
                if pos==1 or pos==3:
                    print("\r[+] You are under attack...[-]",end="")
                    pos+=1
                elif pos==2:
                    print("\r[+] You are under attack...[/]",end="")
                    pos+=1
                else:
                    print("\r[+] You are under attack...[\]",end="")
                    pos=1
        except IndexError:
            pass

def sniff(interface):
    # Monitors all the packets through the interaface                       #prn to execute another function when it catches a packet
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)     #store=False for not store the output,


# main code
options=get_arguements()
pos=1
sniff(options.interface)
