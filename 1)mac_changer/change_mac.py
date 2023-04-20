#!/usr/bin/env python3                                                          

import subprocess                                                               
import optparse                                                                 
import re                                                                       

 
def get_arguements():
    # Parse the arguements from command line
    parser = optparse.OptionParser()                                           
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change Mac Address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New Mac Address")  
    (options,arguements)=parser.parse_args()                                 
                                           
    # Checkimg whether both interface and mac address is specified
    if not options.interface:
        parser.error("[-]Please specify an interface,use --help for more info")
    elif not options.new_mac:
        parser.error("[-]Please specify an new mac,use --help for more info")
    return options


def change_mac(interface,new_mac):
    # Changes the mac addess
    print("[+]Changing mac address for " + interface + " to " + new_mac+".")        
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

def get_current_mac(interface):
    # Extract the changed mac address 
    ifconfig_result = subprocess.check_output(["ifconfig",interface])         
    searched_mac_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result.decode())

    if searched_mac_result:
        return searched_mac_result.group(0)                                      #group(0) for 1st found mac,if there are multiple matched string
    else:
        print("\033[31m[-]Could not read Mac address\033[00m")


# main code
try:
    options=get_arguements()                                                        

    current_mac=get_current_mac(options.interface)                                   
    print("Current MAC = " + current_mac)

    change_mac(options.interface, options.new_mac)                                    

    current_mac=get_current_mac(options.interface)                                  

                                                                                
    if current_mac==options.new_mac:
        print("\033[32m[+]Mac address is successfully changed.\033[00m\nNEW MAC = " + current_mac)
    else:
        print("\033[31m[-]Mac address did not get changed\033[00m")

except Exception as error:
    print("\033[31m[-] Error occured quitting >> \033[00m")
    print(error)




