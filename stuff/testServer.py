from socket import *

serverSocket = socket(AF_INET,SOCK_STREAM)
serverSocket.bind(("",62033))

serverSocket.listen(1)

while True:
	conn, addr = serverSocket.accept()

	req = conn.recv(4)

	if req == "DDOS":
		conn.send("GO")

	ok = conn.recv(2)
	if ok == "OK":
		print "Working"
	
	fin = conn.recv(3)
	if fin == "FIN":
		conn.close()
