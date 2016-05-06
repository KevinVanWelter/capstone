#! /usr/bin/python

import socket
import threading
import time
import os

#create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#get local machine namme
host = ""
port = 62033

print host

#bind to the port
s.bind((host,port))

#queue up to 2 requests
s.listen(2)

while True:
	#establish a connection
	c,addr = s.accept()
	print "Connection from: " , addr
	
	# receive name of client
	confir = c.recv(4)
	
	# Control DDoS Script
	if (confir == 'DDOS'):
		
		# Call the script to parse logs into json
		os.system("../Parsing/parselogs.sh")

		print "DDoS Client Connected!"
		
		# Let the DDoS  client execute
		c.send('GO')
		
		# receive OK signal
		confir2 = c.recv(2)

		if confir2:
			fin = c.recv(3)
			if fin:
				print "Client Done"
				
				# Close connection and sleep
				c.close()
				time.sleep(30)
	else:
		print "Analysis Client Connected!"
		c.close()

	
