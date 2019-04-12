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
from itertools import islice
import time
import datetime
import threading

#
# Global variables
#
username=""					#This is the name of the user
userStatus="START"			#This is the status of the user: START, NAMED, JOINED,CONNECTED, TERMINATED.
clientSkt = ""				#This is the client(user) socket
serverIP = ""				#The IP address of the Room server
serverPort = ""				#The port number listened by the Room server,
listeningPort = ""			#The listening port number used by the P2PChat program
myIP = ""					#The IP address of the client socket
roomname=""					#This is the chatroom's name
memberList=[]				#This is the list of the members in the chatroom
memberHashs=[]				#This is array storing the hash values for each member of the group
memberListHash=""			#This is a uniquely identified hash value for the membership list;
forwardLink = ()			#This is a tuple containing information of the forward linked client

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
	
class theListenThread(threading.Thread): #listen to Poke
	def __init__(self):
		threading.Thread.__init__(self)
		
	def run(self):
		udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM) #create a UDP socket
		for member in memberList: 
			if member[0] == username: #bind to address and port
				udp_address=member[1]
				udp_port=member[2]
				udp_socket.bind((udp_address, int(udp_port)))
				udp_size = 1024
				udp_respond =  "A::\r\n"
		while(True):
			try:
				udp_client_pair = udp_socket.recvfrom(udp_size)
			except socket.error as err:
				print("Error:", err)
			
			
			if udp_client_pair:
				CmdWin.insert(1.0, "\n")
				udp_client_msg = udp_client_pair[0].decode("ascii")
				print(str(udp_client_msg))
				udp_client_ip = udp_client_pair[1]
				udp_client_name = udp_client_msg.split("::")[0].split(':')[2]
				CmdWin.insert(1.0, "\nReceived a poke from " + udp_client_name)
				MsgWin.insert(1.0, "\n [" + udp_client_name+ "]Poke ")
				udp_socket.sendto(udp_respond.encode("ascii"), udp_client_ip) #send reply



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
		clientSkt.send(msg.encode("ascii"))							#Send list request to room server
		res = clientSkt.recv(1024)									#Get respond from room server
		res = str(res.decode("ascii"))
		if res:
			if res[0] == 'G':										#Normal message
				res = res[2:-4]										#Get substring: Start form the third character and remove the last 4 characters, i.e. "::\r\n".
				if len(res) > 0:									#One or more active chatrooms
					rooms = res.split(":")							#Store each chatroom's name into a list
					for room in rooms:
						CmdWin.insert(1.0, "\n\t"+room)
					CmdWin.insert(1.0, "\nActive chatroom list:")	#Print out all the active chatrooms
				else:
					CmdWin.insert(1.0, "\nThere is no active chatroom")
			elif res[0] == 'F': 									#Error message from the server
				res = res[2:-4]
				CmdWin.insert(1.0, "\ndo_List(): Fetching chatroom list error: " + res)

		else:														#If we don't get res, there is a socket error
			raise socket.error("\ndo_List(): Respond is null. Socket Error")	
	except socket.error as err:										#There is an error when connecting to room server
		CmdWin.insert(1.0, "\ndo_List(): Sending message Error")
		clientSkt.close()											#Close current client socket
		_thread.start_new_thread (serverConnect, (do_List, ))		#Start a new thread to make a connection with the room server and call do_List again

def chunk(it, size):												#This function split an array into small chuncks with input size
    it = iter(it)
    return iter(lambda: tuple(islice(it, size)), ())

def do_Join():
	global clientSkt
	global userStatus
	global username
	global roomname
	global myIP
	global listeningPort
	global memberList
	global memberListHash 
	
	if username == "": 															#Check whether the user name is set
		CmdWin.insert(1.0, "\nPlease set username before joining chatroom")
		return
	
	if userentry.get():															#Check whether the user has input chatroom's name
		roomname = userentry.get()
	else:
		CmdWin.insert(1.0, "\nEnter chatroom's name")
		return

	if userStatus == "JOINED" or userStatus == "CONNECTED": 					#Check whether the user has joined a chatroom
		CmdWin.insert(1.0, "\nYou have already joined or connected to a chatroom")
		return	
	else:
		msg = "J:"+roomname+":"+username+":"+myIP+":"+listeningPort+"::\r\n"	#Create Join request
		try:																	#Try to send JOIN request to room server
			clientSkt.send(msg.encode("ascii"))
			res = clientSkt.recv(1024)
			res = str(res.decode("ascii"))
			if res:																#If we get response sucessfully
				if res[0] == "M":												#Normal message
					res = res[2:-4]												#Get substring: Start form the third character and remove the last 4 characters, i.e. "::\r\n".
					mList = res.split(":")										#Get members in the chatroom
					
					memberListHash = mList[0]									#Store unique membership hash
					userStatus = "JOINED"										#Update the client status to JOINED
					userentry.delete(0, END)									#Clear the input entry
					
					CmdWin.insert(1.0, "\nJoined chatroom: "+roomname)
					for member in chunk(mList[1:], 3):							#Get rid of the "MSID" in the list and chunk it into a list of smaller lists: [username, IP, port]
						memberList.append(member)
						CmdWin.insert(1.0, "\n\t"+str(member))					#Print out membership list
					CmdWin.insert(1.0, "\nMembers in this chatroom:")

					_thread.start_new_thread (keepAliveProcedure, ())			#Start a new thread runnning the keepAliveProcedure
					_thread.start_new_thread (serverProcedure, ())				#Start a new thread runnning the serverProcedure
					findP2PPeer(memberList)										#Select a P2PChat peer for initiating a TCP connection
					threadListen = theListenThread()
					threadListen.start()


				elif res[0] == "F":												#Get an error message from the server
					res = res[2:-4]
					CmdWin.insert(1.0, "\ndo_Join(): Join chatroom Error: " + res)
			else:																#Send JOIN request to server failed
				raise socket.error("\ndo_Join(): Respond is null. Socket Error")	


		except socket.error as err:												#There is an error when connecting to room server
			CmdWin.insert(1.0, "\ndo_Join(): Sending message Error")
			clientSkt.close()													#Close current client socket
			_thread.start_new_thread (serverConnect, (do_Join, ))				#Start a new thread to make a connection with the room server and call do_Join again
			
#This function resends the JOIN request to the Room server in every 20 seconds
#in order to indicate the P2PChat peer is still an active member in that chatroom group.
def keepAliveProcedure():
	global userStatus
	CmdWin.insert(1.0, "\nkeepAliveProcedure")
	while clientSkt:										#Indicate this P2PChat peer is still an active member
		updateMemberList("keepAliveProcedure")				#Perform JOIN and update membership list		
		if userStatus == "JOINED" or not forwardLink:		#If client is JOINED but not CONNECTED, keep looking for a peer
			global memberList
			findP2PPeer(memberList)
		time.sleep(20)										#Every 20 seconds

#This function resends the JOIN request to the Room server.
#It also handles the updated membership list.	
def updateMemberList(*src):
	global clientSkt
	global username
	global roomname
	global myIP
	global listeningPort
	global memberList
	global memberListHash 
	msg = "J:"+roomname+":"+username+":"+myIP+":"+listeningPort+"::\r\n"	#Generate JOIN request
	try:
		clientSkt.send(msg.encode("ascii"))
		res = clientSkt.recv(1024)
		res = str(res.decode("ascii"))
		if res:
			if res[0] == 'M':												#Normal message
				now = datetime.datetime.now()								#Get current time
				print(src, " updateMemberList at ", now.strftime("%Y-%m-%d %H:%M:%S"))
				res = res[2:-4]
				mList = res.split(":")
				if memberListHash != mList[0]:								#If the membership list has been changed
					memberListHash = mList[0]								#Update stored hash value
					memberList = []
					for member in chunk(mList[1:], 3):
						memberList.append(member)
					print("Membership list is updated")
					updateMemberHashs(memberList)								#Calculate hash values for each member in the group
				return True
			elif res[0] == 'F':												#Get an error message
				res = res[2:-4]
				CmdWin.insert(1.0, "\nupdateMemberList() JOIN Error")
				return False
		else:
			return False
	except:
		CmdWin.insert(1.0, "\ndo_Join(): Sending message Error")
		clientSkt.close()	
		_thread.start_new_thread (serverConnect, (updateMemberList, ))		#Start a new thread to make a connection with the room server


#This function calculates a hash value for each member in the list and store them in memberHashs
def updateMemberHashs(memberList):
	global memberHashs 
	global username
	memberHashs = []
	for member in memberList:
		if member[0] == username:										#Find the information (name, IP, Port) of the current user						
			myInfo = member 
		memInfo = ""									
		for info in member:
			memInfo = memInfo + info									#concatenate the member information
		memberHashs.append((member,sdbm_hash(memInfo)))					#Append (the member info, hash value)to the memberHashs array
	memberHashs = sorted(memberHashs, key=lambda tup: tup[1])			#sort the array by the hash value
	return myInfo

def serverProcedure():
	CmdWin.insert(1.0, "\nserverProcedure()")

def findP2PPeer(memberList):
	CmdWin.insert(1.0, "\nfindP2PPeer()")

def do_Send():
	CmdWin.insert(1.0, "\nPress Send")


def do_Poke():
	global nickname
	if userStatus == "JOINED" or userStatus == "CONNECTED": 
		if userentry.get():															#Check whether the user has input the nickname
			nickname = userentry.get()
			userentry.delete(0, END)
			if nickname==username:
				CmdWin.insert(1.0, "\nError: You cannot poke yourself!")
			else:
				exist=True
				for member in memberList:
					if member[0] == nickname:
						msg = "K:"+roomname+":"+username+"::\r\n"
						#CmdWin.insert(1.0, "\n\t"+msg)
						exist=False
						addressOfPeer=member[1]
						portOfPeer=member[2]
						#CmdWin.insert(1.0, "\n\t hello"+str(addressOfPeer)+str(portOfPeer))
						sockPoke=socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #create a UDP socket
						sockPoke.sendto(msg.encode("ascii"), (addressOfPeer, int(portOfPeer)))
						CmdWin.insert(1.0, "\nA Poke has been sent successfully to "+nickname)
						
						sockPoke.settimeout(2) #set 2s timeout
						try:
							udp_server_respond = sockPoke.recv(1024).decode("ascii")
							CmdWin.insert(1.0, "\nACK Received from "+ nickname)
						except socket.timeout as e:
							CmdWin.insert(1.0, "\nTime out!")
			if exist:
				CmdWin.insert(1.0, "\nError"+nickname+"is not in the chatroom!")
		
		else:#print all pees in the room if there's no nickname input
			CmdWin.insert(1.0, "\n\tTo Whom do you want to send the Poke?")
			for member in memberList:
				CmdWin.insert(1.0, "\n\t"+member[0])
		
		
		
	if userStatus != "JOINED" and userStatus != "CONNECTED": 
		CmdWin.insert(1.0, "\nError: You should join a chatroom first!")
				


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
		myIP = clientSkt.getsockname()[0]
		CmdWin.insert(1.0, "\nserverConnect(): Successful")
	except socket.error as emsg:
		CmdWin.insert(1.0, "\nserverConnect(): Connecting to Server Error")
		sys.exit(1)
	callback()

if __name__ == "__main__":
	main()

