#!/usr/bin/env python3

import scapy.all as scapy
import optparse,subprocess,re

def get_arguements():
    # Parse the arguements from command line
    parser = optparse.OptionParser()                                             
    parser.add_option("-i", "--interface", dest="interface", help="Interface")           
    options=parser.parse_args() [0]                                               

    # checks required options are provided
    if not options.interface:
        parser.error("[-]Please specify the interface,use --help for more info")

    return options


def get_mac(ip,interface):
    # Creates the ARP request to get the real mac address
    arp_request=scapy.ARP(pdst=ip)                                               #for creating arp packet
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")                               #for creating broadcast packet
    arp_request_broadcast=broadcast/arp_request                                  #appending both packets
    answered_list=scapy.srp(arp_request_broadcast,timeout=1,iface=interface,verbose=False) [0]   

    return answered_list[0][1].hwsrc


def process_sniffed_packet(packet):                                          
    # Detects the arp response packet on our interface
    if packet.haslayer(scapy.ARP):
        response_source_ip = packet[scapy.ARP].psrc
        global myip
        if packet[scapy.ARP].op == 2 and response_source_ip != myip:
            response_mac=packet[scapy.ARP].hwsrc
            real_mac=get_mac(response_source_ip,options.interface)
            if real_mac!=response_mac:
                print("[+] You are under attack!!")


def sniff(interface): 
    # Monitors all the packets through the interaface                            #prn to execute another function when it catches a packet
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)        #store=False for not store the output,


def get_myip():
    # Identifies ip address of the interface
    ifconfig_output = subprocess.check_output("ifconfig "+options.interface+" | grep inet",shell=True)
    searched_ip_result = re.search(r"(?:inet )(\d*\.\d*\.\d*\.\d*)", ifconfig_output)
    if searched_ip_result:
        return searched_ip_result.group(1)


# main code
options=get_arguements()
myip=get_myip()
sniff(options.interface)
