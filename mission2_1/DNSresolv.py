import socket
import struct
import sys
import ssl
from dns import resolver

ISP_PORT = 8000
ISP_HOST = "10.4.7.5"
ROOT_DNS = "10.4.7.6"

res = resolver.Resolver()
res.nameserver = [ROOT_DNS]
answers = res.query(sys.argv[1], source_port=5300)
data = None
for rdata in answers:
	data = rdata.address
print(data)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)
sock.connect((data, 9000))
while True:
	sock.send("GET / HTTP/1.0\r\n\r\n")
	print(sock.recv(4096))
wrapper.close()
