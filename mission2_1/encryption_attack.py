import sys
import nfqueue
import socket
from scapy.all import *
from scapy.layers.inet import IP
import encode
import decode

def encrypt(i, p):
	data = p.get_data()
	pckt = IP(data)
	print(pckt[IP].src)
	ip = IP()
	udp = UDP()
	proto = pckt.proto
	p.set_verdict(nfqueue.NF_DROP)
	if (proto is 0x11 and pckt[UDP].dport == 53):
		qd = pckt[UDP].payload
		print('qd: ', qd)
		qname = qd[DNSQR].qname
		print(qname)
		#encrypt
		#qname = encode.main(qname)
		print(qname)
		ip.src = pckt[IP].src
		ip.dst = pckt[IP].dst
		udp.sport = pckt[UDP].sport
		print('sport: ', udp.sport)
		udp.dport = 5300
		dns = DNS(id=qd.id, opcode="QUERY", aa=0L, tc=0L, rd=1L, ra=0L, z=0L, qr=0, qdcount=1, ancount=0, arcount=0, nscount = 0, rcode = 0)
		dnsqr = DNSQR(qname=qname, qtype="A", qclass="IN")
		dns.qd = dnsqr
		print('dns: ', dns)
		send(ip/udp/dns)
	if (proto is 0x11 and pckt[UDP].dport == 2000):
		qd = pckt[UDP].payload
		print('qd: ', qd)
		qname = qd[DNSQR].qname
		ip.src = pckt[IP].dst
		ip.dst = "178.168.1.5"
		udp.sport = 5300
		udp.dport = 5300
		originalIP = qd.an.rdata
		print(originalIP)
		#decrypt
		#originalIP = decode.main(originalIP)
		print(originalIP)
		dns = DNS(id = qd.id, qr=1, qdcount=1, ancount=1, arcount=1, nscount=1, rcode=0)
		dns.qd = DNSQR(qname=qname, qtype="A", qclass="IN")
		dns.an = DNSRR(rrname=qname, ttl=257540, rdlen=4, rdata=originalIP)
		dns.ns = DNSRR(rrname=qname, ttl=257540, rdlen=4, rdata=originalIP)
		dns.ar = DNSRR(rrname=qname, ttl=257540, rdlen=4, rdata=originalIP)
		send(ip/udp/dns)
	if (proto is 0x11 and pckt[UDP].dport == 5300):
		qd = DNS(pckt[UDP].payload.load)
		print('qd', qd)
		originalIP = qd.an.rdata
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(10)
		sock.connect((originalIP, 9000))
		while True:
			sock.send("GET / HTTP/1.0\r\n\r\n")
			print(sock.recv(4096))
		sock.close()

q = nfqueue.queue()
q.open()
q.bind(socket.AF_INET)
q.set_callback(encrypt)
q.create_queue(0)
try:
	q.try_run()
except KeyboardInterrupt:
	q.unbind(socket.AF_INET)
	q.close()
