from netfilterqueue import NetfilterQueue
from scapy.all import RTP
from scapy.all import IP
from scapy.all import *
import signal
import os
from sys import argv, exit, stdout
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

aesgcm = ''
nfqueue = NetfilterQueue()
ip = ''
message = ''
encr_msg = ''
first = True #se true allora è il primo pacchetto
last = False #se true allora è l'ultimo pacchetto
ID = 1
lastIndex= 10000


def callback(pkt): #qui ricevo il pacchetto e devo controllare se è rtp
	global first, last, ID, encr_msg, lastIndex
	packet = IP(pkt.get_payload())
	pkt.drop()
	if(packet.haslayer("UDP") and last == False and len(encr_msg)> 0): #il pacchetto ha udp, non è l'ultimo, la lunghezza del messaggio è > 0
		rtp = RTP(packet["UDP"].payload)
		if(rtp.haslayer("Raw")): 
			if(len(encr_msg) > 0 and len(rtp["Raw"].load) > 0): 
				if(first == True):
					rtp["Raw"].load = b'\xbb\xbb'+rtp["Raw"].load[2:]
					first = False
					ID += 1
					print(first)
				elif(ID < lastIndex and first == False):
					ind = format(ID, '#04x')
					if(len(ind) % 2 != 0): 
						ind = ind[:2]+'0'+ind[2:]
						rtp["Raw"].load = bytes.fromhex(ind[2:])+(rtp["Raw"].load)[2:]
					else: rtp["Raw"].load = bytes.fromhex(ind[2:])+(rtp["Raw"].load)[1:]
					ID += 1

				elif(ID == lastIndex):
					rtp["Raw"].load = b'\xbb\xbb'+(rtp["Raw"].load)[2:]
					last = True
					
				length = len(rtp["Raw"].load)
				chload = rtp["Raw"].load[length-1:]
				chload, encr_msg = change(chload, encr_msg)
				rtp["Raw"].load = rtp["Raw"].load[:length-1]+chload
				packet["UDP"].chksum = None
				packet["UDP"].payload = rtp
				#print((rtp["Raw"].load)[:2])
		
	send(packet, verbose=False)
	if(last): stop()
	return first, last, ID, lastIndex

def change(load, encr_msg): #il payload viene modificato
	if(len(encr_msg) == 0): return load, encr_msg
	string = chexdump(load, True)
	lista = (string.replace(',', '').split())
	i = 0
	for l in lista:
		numbit = bin(int(l, 16))[2:].zfill(8)
		if(numbit[7] != encr_msg[i]): numbit = numbit[:7] + encr_msg[i]
		lista[i] = int(numbit, 2)
		i += 1
	load = bytes(lista)

	encr_msg = encr_msg[1:]
	return load, encr_msg

def encrypt(message, key, ip): #il messaggio viene criptato
	global encr_msg, lastIndex
	try:
	    f = open(ip+'.txt', 'r+')
	    value = f.read()
	    iv = value.encode()
	    newval = int(value)+1
	    f.seek(0)
	    f.write(str(newval))
	    f.close()
	except FileNotFoundError:
		f = open(ip+".txt","w+")
		iv = b'1111111111111'
		value = 1111111111112
		f.write(str(value))
		f.close()

	cipher = aesgcm.encrypt(iv, message.encode(), b"")
	print("cipher: ", cipher)
	encr_msg = ''.join('{0:08b}'.format(x,'b') for x in cipher) #encoding + encryption
	#encr_msg = ''.join('{0:08b}'.format(x,'b') for x in message.encode()) #solo encoding
	lastIndex = len(encr_msg)
	print("encr_msg: ", encr_msg)
	print("last index: ", lastIndex)
	return encr_msg, lastIndex

def stop(): #funzione per "staccare" la nfqueue e chiudere il processo
	global nfqueue, aesgcm
	print("[*] SENT")
	print("[*] AESGCM = ", aesgcm)
	nfqueue.unbind()
	os.write(1, b"")
	os._exit(0)

def main(ip_receiver, msg, k): #funzione iniziale
	global nfqueue, ip, message, aesgcm
	print("[*] IP = ", ip_receiver)
	print("[*] MESSAGE TO ENCODE = ", message)

	ip = ip_receiver 
	message = msg 
	key = k
	aesgcm = AESGCM(key.encode())
	print(aesgcm)
	os.write(1, message.encode())
	encrypt(message, aesgcm, ip)
	os.system(('iptables -t mangle -A POSTROUTING -p udp -d {} -j NFQUEUE --queue-num 144').format(ip))
	nfqueue.bind(144, callback)
	try: 
		nfqueue.run()
	except KeyboardInterrupt:
		print("[*] INTERRUPTED")

if __name__ == '__main__':
	main(ip_receiver=argv[1], msg=argv[2], k=argv[3])