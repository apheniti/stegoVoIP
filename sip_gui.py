from tkinter import *
import sys
import subprocess
import os

LARGE_FONT=("Verdana", 12)
MEDIUM_FONT=("Verdana", 10)
SMALL_FONT=("Verdana", 9)
root = Tk()
msg = StringVar()
ip_sender = StringVar()
ip_receiver = StringVar()
key = StringVar()
decoded = ''
s = None

def encoding():
	global entry_message
	print("[*] ENCODE. . . ")
	bdecode.place_forget()
	bencode.place_forget()
	home.place_forget()

	dest = Label(window, text="Send To: ", font=MEDIUM_FONT)
	dest.place(x=20, y=20)
	entry_sendTo.place(x=100, y=20)
	entry_sendTo.focus_set()
	entry_sendTo.delete(0, END)
	entry_sendTo.insert(0, "insert receiver")
	
	label_msg = Label(window, text="Message: ", font=MEDIUM_FONT)
	label_msg.place(x=20, y=50)
	entry_message.place(x=100, y=50)
	entry_message.focus_set()
	entry_message.delete(0, END)
	entry_message.insert(0, "insert message")
	
	label_key = Label(window, text="Key: ", font=MEDIUM_FONT)
	label_key.place(x=20, y=80)
	entry_key.place(x=100, y=80)
	entry_key.focus_set()
	entry_key.delete(0, END)
	entry_key.insert(0, "insert key (16 chars)")

	estart.place(x=20, y=140)
	stop = Button(window, text="STOP", command=stopApp, font=LARGE_FONT, width=6) 
	stop.place(x=20, y = 175)

def decoding():
	print("[*] DECODE. . .")
	bdecode.place_forget()
	bencode.place_forget()
	home.place_forget()
	sender = Label(window, text="Sent From:", font=MEDIUM_FONT)
	sender.place(x=20, y=20)
	entry_receiveFrom.place(x=100, y=20)
	entry_receiveFrom.focus_set()
	entry_receiveFrom.delete(0, END)
	entry_receiveFrom.insert(0, "insert sender")

	label_key = Label(window, text="Key: ", font=MEDIUM_FONT)
	label_key.place(x=20, y=50)
	entry_key.place(x=100, y=50)
	entry_key.focus_set()
	entry_key.delete(0, END)
	entry_key.insert(0, "insert key (16 chars)")

	label_msg = Label(window, text="Message: ", font=MEDIUM_FONT)
	label_msg.place(x=20, y=80)	
	scroll = Scrollbar(window, command=decoded_message.yview)
	decoded_message.place(x=100, y=80)
	decoded = "Decoded message . . ."
	decoded_message.insert(END, decoded)

	dstart = Button(window, text="START", command=startDecode, font=LARGE_FONT, width=6) 
	dstart.place(x=20, y=140)
	stop = Button(window, text="STOP", command=stopApp, font=LARGE_FONT, width=6) 
	stop.place(x=20, y = 175)


def startEncode():
	global s
	print("[*] ENCODING...")
	msg = entry_message.get()
	ip_receiver = entry_sendTo.get()
	key = entry_key.get()
	s = subprocess.Popen(["python3", "encode.py", ip_receiver, msg, key], stdout=subprocess.PIPE, bufsize=1)
	sys.stdout.flush()
	out = s.communicate()[0]
	print("[*] MESSAGE SENT!")
	print("OUTPUT: ", out)
	done = Label(window, text="MESSAGE SENT.",  font=LARGE_FONT) 
	done.place(x=20, y=110)
	estart["text"] = "OTHER?"
	s.kill() #togli il commento quando reinserisci stdout

def startDecode():
	global s, key
	print("[*] DECODING...")
	ip_sender = entry_receiveFrom.get()
	key = entry_key.get()
	s = subprocess.Popen(["python3", "decode.py", ip_sender, key], stdout=subprocess.PIPE, universal_newlines=True)
	sys.stdout.flush()
	value = s.communicate()[0]
	done = Label(window, text="MESSAGE RECEIVED.",  font=LARGE_FONT) 
	done.place(x=20, y=120)
	decoded_message.delete('1.0', END)
	decoded_message.insert(END, value.encode())
	dstart["text"] = "OTHER?"
	s.kill() #togli il commento quando reinserisci stdout

def stopApp():
	global s
	print("[*] STOP EVERYTHING!")
	os.system("iptables -F")
	os.system("iptables -X")
	os.system("iptables -t mangle -F")
	os.system("iptables -t mangle -X")
	if(s is not None): s.kill()
	root.destroy()

window = Canvas(root, width = 290, height=220)
window.focus_set()
window.pack()
root.title("StegoVOIP")


home = Label(window, text="Click on the service:", font=LARGE_FONT)
home.place(x=55, y=60)#, anchor="center")
bencode = Button(window, text="ENCODE", command=encoding, font=LARGE_FONT) 
bencode.place(x=45, y=100)
bdecode = Button(window, text="DECODE", command=decoding, font=LARGE_FONT)
bdecode.place(x=155, y=100)
estart = Button(window, text="START", command=startEncode, font=LARGE_FONT, width=6) 
dstart = Button(window, text="START", command=startDecode, font=LARGE_FONT, width=6) 

entry_message = Entry(window, textvariable=msg, font=MEDIUM_FONT, width=20)
entry_sendTo = Entry(window, textvariable=ip_receiver, font=MEDIUM_FONT, width=20)
entry_key = Entry(window, textvariable=key, font=MEDIUM_FONT, width=20)
entry_receiveFrom = Entry(window, textvariable=ip_sender, font=MEDIUM_FONT, width=20)

decoded_message = Text(window, height=2, width=20, font=MEDIUM_FONT)

root.mainloop()

