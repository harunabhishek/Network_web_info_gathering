#!/usr/bin/env python3
# finds other subdomains and directories in a domain (may be hidden)


import requests


def request_url(url):
    # Sends the request to the url and return url if there is a response
    try:
        get_response = requests.get(url)
        #print(get_response)
        return get_response
    except KeyboardInterrupt:
        print("[+] Detected Ctrl + C .........Quitting")
        exit()
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.InvalidURL:
        pass
    except urllib3.exceptions.LocationParseError:
        pass
    except Exception as error:
        print(str(error))


def read_word_url(domain, file_name):
    # Reads words from the file and built the url
    with open(file_name, "r") as wordlist_file:
        # file_content = wordlist_file.read()                     #this will read whole file as 1 string
        for line in wordlist_file:
            word = line.strip()
            # new_url = "https://" + word + "." + domain          #for finding subdomains
            # new_url = "http://" + domain + "/" + word           #for finding dirs and files
            response = request_url(new_url)
            if response:
                print(new_url)


# main code
domain = "google.com"                                               # domain that is to be searched
# file_name = "subdomains.txt"                                      # file containing subdomains words
file_name = "files_and_dirs_wordlist.txt"                           # file containing words realated to directories and files
read_word_url(domain, file_name)


