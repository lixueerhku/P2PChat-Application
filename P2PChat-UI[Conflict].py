#!/usr/bin/python3

# Student name and No.:
# Student name and No.:
# Development platform:
# Python version:
# Version:


from tkinter import *
import sys
import socket
import _thread

#
# Global variables
#
username=""					#This is the name of the user
userStatus="START"			#This is the status of the user: START, NAMED, JOINED,CONNECTED, TERMINATED.
clientSkt = ""				#This is the client(user) socket
serverIP = ""				#The IP address of the Room server
serverPort = ""				#The port number listened by the Room server,
listeningPort = ""					#The listening port number used by the P2PChat program
myIP = ""					#The IP address of the client socket
roomname=""					#This is the chatroom's name

#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address), 
# and str(Port) to form a string that be the input 
# to this hash function
#
def sdbm_hash(instr):
	hash = 0
	for c in instr:
		hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff


#
# Functions to handle user input
#

def do_User():
	global userStatus
	if userentry.get():												#userentry.get() is not empty 
		if userStatus != "JOINED" and userStatus != "CONNECTED":	#The user hasn't joined any chatroom
			global username
			username = userentry.get()								#Store the input name in the global variable
			userStatus = "NAMED"									#Changed the userStatus to NAMED
			outstr = "\n[User] username: "+username					#Print the username message in command window
			CmdWin.insert(1.0, outstr)
			userentry.delete(0, END)

		else:
			CmdWin.insert(1.0, "\nYou have joined a chatroom. Cannot change your name!")		#Cannot change name after joining a chatroom
	else:
		CmdWin.insert(1.0, "\nPlease enter your name")				#The user didn't not enter username



def do_List():
	msg = "L::\r\n"													#List request. To get the list of active chatroom groups.
	try:
		clientSkt.send(msg.encode("ascii"))						#Send list request to room server
		res = clientSkt.recv(1024)								#Get respond from room server
		res = str(res.decode("ascii"))
		if res:
			if res[0] == 'G':										#Normal message
				res = res[2:-4]										#Get substring: Start form the third character and remove the last 4 characters, i.e. "::\r\n".
				if len(res) > 0:									#One or more active chatrooms
					rooms = res.split(":")							#Store each chatroom's name into a list
					CmdWin.insert(1.0, "\nActive chatroom list:")	#Print out all the active chatrooms
					for room in rooms:
						CmdWin.insert(1.0, "\n\t"+room)
				else:
					CmdWin.insert(1.0, "\nThere is no active chatroom")
			elif res[0] == 'F': 									#Error message from the server
				res = res[2:-4]
				CmdWin.insert(1.0, "\nFetching chatroom list error: " + res)

		else:														#If we don't get response, there is a socket error
			raise socket.error("Socket Error")	
	except socket.error as err:										#There is an error when connecting to room server
		CmdWin.insert(1.0, "\nConnection to room server Error")
		clientSkt.close()										#Close current room server socket
		_thread.start_new_thread (serverConnect, (do_List, ))		#Start a new thread to make a connection with the room server and call do_List again



def do_Join():
	CmdWin.insert(1.0, "\nPress JOIN")

	global userStatus
	global username
	global roomname
	global myIP
	global listeningPort
	
	if username == "": 												#Check whether the user name is set
		CmdWin.insert(1.0, "\nPlease set username before joining chatroom")
		return
	
	if userentry.get():												#Check whether the user has input chatroom's name
		roomname = userentry.get()
	else:
		CmdWin.insert(1.0, "\nEnter chatroom's name")
		return

	if userStatus == "JOINED" or userStatus == "CONNECTED": 		#Check whether the user has joined a chatroom
		CmdWin.insert(1.0, "\nYou have already joined or connected to a chatroom")
		return	
	else:



	


def do_Send():
	CmdWin.insert(1.0, "\nPress Send")


def do_Poke():
	CmdWin.insert(1.0, "\nPress Poke")


def do_Quit():
	CmdWin.insert(1.0, "\nPress Quit")
	sys.exit(0)


#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='6', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='6', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='6', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='6', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt06 = Button(topmidframe, width='6', relief=RAISED, text="Poke", command=do_Poke)
Butt06.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='6', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)

def main():
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)
	else:
		global serverIP
		global serverPort 
		global listeningPort 
		
		serverIP = sys.argv[1]
		serverPort = sys.argv[2]
		listeningPort= sys.argv[3]
		_thread.start_new_thread(serverConnect, (do_User,))	#Create a new thread for connecting server

	win.mainloop()

def serverConnect(callback):
	global clientSkt
	global serverIP
	global serverPort
	global myIP
	
	try:
		clientSkt = socket.socket()
		clientSkt.connect((serverIP, int(serverPort)))
		myIP = roomServerSocket.getsockname()[0]
		CmdWin.insert(1.0, "\nserverConnect(): Successful")
	except socket.error as emsg:
		CmdWin.insert(1.0, "\nserverConnect(): Connecting to Server Error")
		sys.exit(1)
	callback()

if __name__ == "__main__":
	main()

