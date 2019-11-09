from netfilterqueue import NetfilterQueue
from scapy.all import RTP
from scapy.all import IP
from scapy.all import *
import socket
import signal
from sys import argv, stderr, stdout
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

dizionario = {}
nfqueue = NetfilterQueue()
ip = ''
first = True
last = False
todecrypt = bytearray()
index = 1
aesgcm = ''

def callback(pkt):
	global first, last, todecrypt, index, dizionario
	packet = IP(pkt.get_payload())
	pkt.accept()
	if(packet.haslayer("UDP") and last == False):
		rtp = RTP(packet["UDP"].payload)
		if(rtp.haslayer("Raw")):
			length = len(rtp["Raw"].load)
			if(length > 0 and rtp["Raw"].load[:1] == b'\xbb' and first == True):
				toapp = rtp["Raw"].load[length-1:]
				todecrypt.extend(toapp)
				dizionario[0] = toapp
				first = False
				#print(index)
			elif(rtp["Raw"].load[:2] == b'\xbb\xbb' and first == False):
				print("LAST.")
				toapp = rtp["Raw"].load[length-1:]
				dizionario[65535] = toapp
				last = True
				decrypt()
			elif(first == False and last == False):
				if(index >= 255): 
					ind = rtp["Raw"].load[:2]
					#print(int(ind.hex(), 16))
					#print(rtp["Raw"].load[length-1:])
				else: ind = rtp["Raw"].load[:1]
				toapp = rtp["Raw"].load[length-1:]
				dizionario[int(ind.hex(), 16)] = toapp
				#dizionario[index] = toapp
				index += 1
				print("index: ", index)
		else: print("no layer Raw")
	return first, last, index, dizionario

def stop(msg_decr):
	global nfqueue
	nfqueue.unbind()
	os.write(1, msg_decr)
	os._exit(0)

def decrypt(): #funzione per decriptare quanto ottenuto

	global aesgcm, ip, dizionario
	print("[*] AESGCM: ", aesgcm)
	try:
	    f = open(ip+'.txt', 'r+')
	    value = f.read()
	    iv = (value.encode())
	    newval = int(value)+1
	    f.seek(0)
	    f.write(str(newval))
	    f.close()
	except FileNotFoundError:
		f = open(ip+'.txt','w+')
		iv = b'1111111111111'
		value = 1111111111112
		f.write(str(value))
		f.close()
	decifriamo = bytearray()
	for d in sorted(dizionario):
		decifriamo.extend(dizionario[d])
	decr = ''
	decr2 = ''
	for t in decifriamo:
		decr += (format(t, 'b').zfill(8))[7]
	
	binario = int(decr, 2)
	cifrato = binario.to_bytes((binario.bit_length()+7) // 8, 'big')

	messaggio = aesgcm.decrypt(iv, cifrato, b"")
	print("[*] MESSAGE", messaggio)
	stop(messaggio)

def main(ip_s, key):
	global ip, aesgcm
	ip = ip_s
	aesgcm = AESGCM(key.encode())
	print("[*] IP: ", ip)
	print("[*] KEY: ", key)
	os.system(('iptables -I INPUT -p udp -s {} -j NFQUEUE --queue-num 19').format(ip))
	nfqueue.bind(19, callback)
	try:
		nfqueue.run()
	except KeyboardInterrupt:
		print("[*] INTERRUPTED")
	return ip, aesgcm

if __name__ == '__main__':
	main(ip_s = argv[1], key = argv[2])