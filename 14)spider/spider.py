#!/usr/bin/env python3

# Crawl the webpage to find links within the links

import requests, re
import urllib.parse as urlparse



def display_failed_links():
    # Prints the failed link on the webpage
    print("................[-] Failed to request these links............")
    for link in failed_links:
        print(link)


failed_links = []
def request_url(url):
    # Sends the request to link and determine active or failed
    try:
        get_response = requests.get(url)
        #print(get_response)
        if "404" in str(get_response):
            failed_links.append(url)
            return None
        return get_response
    # except requests.exceptions.ConnectionError:
    #     pass
    # except requests.exceptions.InvalidURL:
    #     pass
    # except requests.exceptions.InvalidSchema:
    #     pass
    except Exception:
        failed_links.append(url)
        pass


def extract_links(url):
    # Extracts the links in a webpage                                                               #get response of url
    response = request_url(url)
    if response:
        url_expression = "(?:href='?" + '"?)(.*?)["' + "'\s>]"
        return re.findall(url_expression, response.content.decode(errors="ignore"))                 #filtering url, decode to type mismatch in python3 , errors to ignore if
    else:
        return None

def neglect_links(link):
    # Neglects links that are not url to other webpages
    neglect_extensions = [".png", ".css", ".pdf", ".jpeg", ".jpg", ".exe", ".zip"]
    for neglect_extension in neglect_extensions:
        if neglect_extension in link:
            return True


target_links =[]                                                                                      #list stores found unique links
def crawl(url):
    # Visits the urls on a webpage recursively
    href_links = extract_links(url)
    if href_links:
        for link in href_links:
            # if link not in url
            link = urlparse.urljoin(url, link)                                                  # to join relative links with target url
            if '#' in link:
                link = link.split('#')[0]                                                       # to make filter links with '#' tags
            if url in link and link not in target_links:                                        # filter links to other websites and also checks if link is not in our unique link list
                target_links.append(link)
                print(link)
                flag = neglect_links(link)
                if not flag:
                    crawl(link)                                                                  # recursive calling to check links within links
                # crawl(link)


# main code
target_url = ""                                                                                   # url of website to crawled                                                                  
crawl(target_url)
display_failed_links()