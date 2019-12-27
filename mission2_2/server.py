import socket
import time
import smtplib
import re
import json
import urllib.request

def sendFile(filename):
	f = open(filename, 'r')
	data = f.read()
	c.sendall(str.encode("HTTP/1.0 200 OK\n", 'iso-8859-1'))
	c.sendall(str.encode('Content-Type: text/html\n', 'iso-8859-1'))
	c.send(str.encode('\r\n'))
	for i in range(0, len(data)):
		c.send(data[i].encode())
	f.close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Socket successfully created")

port = 9000

s.bind(('', port))
print ("socket binded to %s" %(port))

s.listen(5)
print("Socket is listening")


while True:

	c, addr = s.accept()
	print("Got connection from", addr)
	request = c.recv(4096)
	decoding = request.decode("utf-8")
	print(decoding)
	filename = 'index.html'
	sendFile(filename)
	time.sleep(2)
	c.close()
