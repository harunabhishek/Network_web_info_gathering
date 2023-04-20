#!/usr/bin/env python3

# First crawls for all the working links in a website and stores them.
# And after that visits every acive links for xss vulnerabilites.



import requests
import urllib.parse as urlparse
import re
from bs4 import BeautifulSoup


class Scanner:
    def __init__(self, url):
        # Intialize all the required variables
        self.target_url = url
        self.session = requests.Session()                                           #creating the session, so it's like opening it in the browsers
        self.target_links = []                                                      #stores all the unique links in a website
        self.failed_links = []
        self.target_links.append(self.target_url)
        # self.target_links.append(self.target_url + '/')

    def store_failed_links(self):
        # Stores all the failed links in a file
        with open("failed_links.txt", "a") as out_file:
            for failed_link in self.failed_links:
                out_file.write(failed_link)
                out_file.write("\n")

    def display_failed_links(self):
        # Displays the failed links on the terminal
        print("................[-] Failed to request these links............")
        for link in self.failed_links:
            print(link)

    def handle_request_url(self, url):
        # Sends request to the url
        try:
            get_response = self.session.get(url)
            if "404" in str(get_response):
                self.failed_links.append(url + " 404")
                return None
            return get_response
        except Exception as error:
            self.failed_links.append(url + " >> " + str(error))
            pass

    def extract_links(self, url):
        # Extracts the links in a webpage
        response = self.handle_request_url(url)
        if response:
            url_expression = "(?:href='?" + '"?)(.*?)["' + "'\s>]"
            return re.findall(url_expression, response.content.decode(errors="ignore"))

    def neglect_links(self, link):
        # Neglects links that are not url to other webpages(eg: links files)
        neglect_extensions = [".png", ".css", ".pdf", ".jpeg", ".jpg", ".exe", ".zip"]
        for neglect_extension in neglect_extensions:
            if neglect_extension in link:
                return True

    def crawl(self, url=None):
        # Crawls for the urls on a webpage recursively
        if url == None:
            url = self.target_url

        href_links = self.extract_links(url)
        if href_links:
            for link in href_links:
                link = urlparse.urljoin(url, link)
                if '#' in link:
                    link = link.split('#')[0]
                if url in link and link not in self.target_links:
                    self.target_links.append(link)
                    print(link)
                    neglect_link_flag = self.neglect_links(link)
                    if not neglect_link_flag:
                        self.crawl(link)
                    # self.crawl(link)


    def extract_forms(self, url):
        # Parse the forms in in requested url
        response = self.session.get(url)
        parse_html = BeautifulSoup(response.content.decode(errors="ignore"))
        return parse_html.find_all("form")


    def submit_form(self, form, value, url):
        # Submit the forms with the test code
        action = form.get("action")
        post_url = urlparse.urljoin(url, action)
        method = form.get("method")
        inputs_list = form.find_all("input")
        post_data = {}
        for input in inputs_list:
            input_name = input.get("name")
            input_value = input.get("value")
            if not input_name:
                input_name = input_value
            input_type = input.get("type")
            if input_type == "submit":
                input_value = input_type
            if input_type == "text":
                input_value = value
            post_data[input_name] = input_value
        if method == "post":
           return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)


    def test_xss_in_links(self,url):
        # Checks for vulnerabilies in links
        xss_test_script = "<sCriPt>alert('xss test')</scRIpt>"
        url = url.replace("=", "=" + xss_test_script)
        response = self.session.get(url)
        # if xss_test_script in response.content:
        #     return True
        return xss_test_script in response.content.decode(errors="ignore")


    def test_xss_in_forms(self, form, url):
        # Checks for vulnerabilites in forms
        xss_test_script = "<sCriPt>alert('xss test')</scRIpt>"
        response = self.submit_form(form, xss_test_script, url)
        return xss_test_script in response.content.decode(errors="ignore")


    def run_vuln_scanner(self):
        # Checks for xss vulnerabilites in web pages with forms
        for link in self.target_links:
            neglect_link_flag = self.neglect_links(link)
            if not neglect_link_flag:
                print("Checking forms in " + link)
                forms = self.extract_forms(link)
                for form in forms:
                    print("[+] Testing form in " + link)
                    vulnerable_to_xss = self.test_xss_in_forms(form, link)
                    if vulnerable_to_xss:
                        print("\n\n[***] Discovered  XSS in form")
                        print(form)
                if "=" in link:
                    vulnerable_to_xss = self.test_xss_in_links(link)
                    if vulnerable_to_xss:
                        print("\n\n[***] Discovered  XSS in link")




# main code
target_url = ""                                                                       # url of website to be scanned  

vuln_scanner = Scanner(target_url)
vuln_scanner.crawl()                                                                  # only crawls for links in a website
vuln_scanner.display_failed_links()                                                     
# vuln_scanner.store_failed_links()
vuln_scanner.run_vuln_scanner()                                                       # scans for xss vulnerablities in a webpage
