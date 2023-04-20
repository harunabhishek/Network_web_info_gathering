#!/usr/bin/env  python3

import optparse, os, time
import scapy.all as scapy


def get_arguements():
    # Parse the arguements from command line
    parser = optparse.OptionParser()                                             
    parser.add_option("-r", "--range", dest="range", help="Range ")              
    parser.add_option("-i","--interface",dest="interface",help="Interface")
    options=parser.parse_args() [0]                                              

    # Checkimg whether range and interface is specified
    if not options.range:
        parser.error("[-]Please specify the range,use --help for more info")
    elif not options.interface:
        parser.error("[-]Please specify an interface,use --help for more info")

    return options

    # scapy.arping(ip)  direct function to scan devices

def scan(ip,interface):
    # Creates and Sends the arp request and receives responses 
    arp_request=scapy.ARP(pdst=ip)                                               #for creating arp packet
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")                               #for creating broadcast packet
    arp_request_broadcast=broadcast/arp_request                                  #appending both packets
    answered_list=scapy.srp(arp_request_broadcast,iface=interface,timeout=2,verbose=False) [0]

    # Created list of responses using Dicitionary
    clients_list=[]                                                              
    for element in answered_list:
        clients_dict={"ip": element[1].psrc,"mac": element[1].hwsrc}
        clients_list.append(clients_dict)                                         

    return clients_list

def print_result(client_list):
    # Print the result in pleasable format
    print("    IP\t\t\tMAC Address\n------------------------------------------")
    i=0;
    str = ""
    for client in client_list:
        if i==0: str=client["ip"] + "\t\t" + client["mac"]; i=1
        else : str = "\033[95m" + client["ip"] + "\t\t" + client["mac"] + "\033[00m"; i=0

        print(str)                                          


#main code

options=get_arguements()
os.system('clear')
try:
    while True:
        client_list=scan(options.range,options.interface)
        print("\n\033[34m" + "Searching devices over : " + "\033[32m" + options.range + "\033[00m\n")
        print_result(client_list)
        time.sleep(5)                               # rescan after 5 seconds                                                
        os.system("clear")

except KeyboardInterrupt:
    print("[+] Ctl+C detected ....Quitting...........\n")
    exit()
except Exception as error:
    print("[-] Some error occurred >>")
    print(error)

