#!/usr/bin/python3

# Student name and No.: Li Xueer 3035332335
# Student name and No.: Liu Yujie 3035329754
# Development platform: Visual Studio Code
# Python version: Python 3.6.4 
# Version: Stage1 and 2 completed
# Date: 2019-April-13


from tkinter import *
import sys
import socket
import threading
from itertools import islice
import time
import datetime
import traceback

#
# Global variables
#
username=""					#This is the name of the user
userStatus="START"			#This is the status of the user: START, NAMED, JOINED,CONNECTED, TERMINATED.
sktToRoomServer = ""		#This is the client socket connected to the room server
serverIP = ""				#The IP address of the Room server
serverPort = ""				#The port number listened by the Room server,
listeningPort = ""			#The listening port number used by the P2PChat program, getsockaddrarg: port must be 0-65535.
myIP = ""					#The IP address of the client socket
roomname=""					#This is the chatroom's name
myHashID=""					#This is the hash ID for the user
memberList=[]				#This is the list of the members in the chatroom
memberHashs=[]				#This is array storing the hash values for each member of the group [((name, IP, Port), hashID)]
memberListHash=""			#This is a uniquely identified hash value for the membership list;
forwardLink = ()			#This is a tuple containing information of the forward linked client: (((name, IP, Port), hashID), forwardSocket)
backLinks=[]				#This is the array of back links, each link stored: [(((name, IP, Port), hashID), socket)]
msgID = 0					#Message ID of the last message used by the user
receivedMsg = []			#This is an array storing the received messages in the form: (sender's hash ID, msgID)
myLock = threading.Lock()	#This is a mutex lock used when entering critical section: receivedMsg

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
	if userentry.get():																			#userentry.get() is not empty 
		if userStatus != "JOINED" and userStatus != "CONNECTED":								#The user hasn't joined any chatroom
			global username
			global myHashID
			global myIP
			global listeningPort
			username = userentry.get()															#Store the input name in the global variable
			userStatus = "NAMED"																#Changed the userStatus to NAMED
			outstr = "\n[User] username: "+username												#Print the username message in command window
			myHashID = sdbm_hash(username+myIP+listeningPort)									#Calculate my hash ID
			CmdWin.insert(1.0, outstr)
			userentry.delete(0, END)

		else:
			CmdWin.insert(1.0, "\nYou have joined a chatroom. Cannot change your name!")		#Cannot change name after joining a chatroom
	else:
		CmdWin.insert(1.0, "\nPlease enter your name")											#The user didn't not enter username


#This function gets the list of chatroom groups registered in the Room server
def do_List():
	msg = "L::\r\n"																				#List request. To get the list of active chatroom groups.
	try:
		sktToRoomServer.send(msg.encode("ascii"))												#Send list request to room server
		res = sktToRoomServer.recv(1024)														#Get respond from room server
		res = str(res.decode("ascii"))
		if res:
			if res[0] == 'G':																	#Normal message
				res = res[2:-4]																	#Get substring: Start form the third character and remove the last 4 characters, i.e. "::\r\n".
				if len(res) > 0:																#One or more active chatrooms
					rooms = res.split(":")														#Store each chatroom's name into a list
					for room in rooms:
						CmdWin.insert(1.0, "\n\t"+room)
					CmdWin.insert(1.0, "\nActive chatroom list:")								#Print out all the active chatrooms
				else:
					CmdWin.insert(1.0, "\nThere is no active chatroom")
			elif res[0] == 'F': 																#Error message from the server
				res = res[2:-4]
				CmdWin.insert(1.0, "\ndo_List(): Fetching chatroom list error: " + res)

		else:																					#If we don't get res, there is a socket error
			raise socket.error("\ndo_List(): Respond is null. Socket Error")	
	except socket.error as err:																	#There is an error when connecting to room server
		CmdWin.insert(1.0, "\ndo_List(): Sending message Error")
		sktToRoomServer.close()																 	#Close current client socket

		serverConnectThread=threading.Thread(target=serverConnect, args=(do_List, )) 			#Start a new thread to make a connection with the room server and call do_List again
		serverConnectThread.setDaemon(True)
		serverConnectThread.start()

#This function split an array into small chuncks with input size
def chunk(it, size):												
    it = iter(it)
    return iter(lambda: tuple(islice(it, size)), ())


#This function let the user join a target chatroom group.
#If there is no such chatroom group, it will first create a new one and let the user join it
def do_Join():
	global sktToRoomServer
	global userStatus
	global username
	global roomname
	global myIP
	global listeningPort
	global memberList
	global memberListHash 
	
	if username == "": 																	 	#Check whether the user name is set
		CmdWin.insert(1.0, "\nPlease set username before joining chatroom")
		return
	
	if userentry.get():																	 	#Check whether the user has input chatroom's name
		roomname = userentry.get()
	else:
		CmdWin.insert(1.0, "\nEnter chatroom's name")
		return

	if userStatus == "JOINED" or userStatus == "CONNECTED": 							 	#Check whether the user has joined a chatroom
		CmdWin.insert(1.0, "\nYou have already joined or connected to a chatroom")
		return	
	else:
		msg = "J:"+roomname+":"+username+":"+myIP+":"+listeningPort+"::\r\n"			 	#Create Join request
		try:																			 	#Try to send JOIN request to room server
			sktToRoomServer.send(msg.encode("ascii"))
			res = sktToRoomServer.recv(1024)
			res = str(res.decode("ascii"))
			if res:																		 	#If we get response sucessfully
				if res[0] == "M":														 	#Normal message
					res = res[2:-4]														 	#Get substring: Start form the third character and remove the last 4 characters, i.e. "::\r\n".
					mList = res.split(":")												 	#Get members in the chatroom
					
					memberListHash = mList[0]											 	#Store unique membership hash
					userStatus = "JOINED"												 	#Update the client status to JOINED
					userentry.delete(0, END)											 	#Clear the input entry
					
					CmdWin.insert(1.0, "\nJoined chatroom: "+roomname)
					for member in chunk(mList[1:], 3):									 	#Get rid of the "MSID" in the list and chunk it into a list of smaller lists: [username, IP, port]
						memberList.append(member)
						CmdWin.insert(1.0, "\n\t"+str(member))							 	#Print out membership list
					CmdWin.insert(1.0, "\nMembers in this chatroom:")

					keepAliveThread = threading.Thread(target=keepAliveProcedure)		 	#Start a new thread runnning the keepAliveProcedure
					keepAliveThread.setDaemon(True)					
					keepAliveThread.start()
					
					serverThread = threading.Thread(target=serverProcedure)				 	#Start a new thread runnning the serverProcedure
					serverThread.setDaemon(True)
					serverThread.start()
					
					findP2PPeer(memberList)												 	#Select a P2PChat peer for initiating a TCP connection
					
					try:
						threadListen = theListenThread()									#Create a thread for UDP server
						threadListen.setDaemon(True)										##When it's a daemon thread, the thread terminates when the main  thread terminates.
						threadListen.start()
					except (KeyboardInterrupt, SystemExit):
						print("\n! Received keyboard interrept, closing threads...")

				elif res[0] == "F":															#Get an error message from the server
					res = res[2:-4]
					CmdWin.insert(1.0, "\ndo_Join(): Join chatroom Error: " + res)
			else:																			#Send JOIN request to server failed
				raise socket.error("\ndo_Join(): Respond is null. Socket Error")	


		except socket.error as err:															#There is an error when connecting to room server
			CmdWin.insert(1.0, "\ndo_Join(): Sending message Error")
			if sktToRoomServer:
				sktToRoomServer.close()														#Close current client socket
			serverConnectThread=threading.Thread(target=serverConnect, args=(do_Join, )) 	#Start a new thread to make a connection with the room server and call do_Join again
			serverConnectThread.setDaemon(True)
			serverConnectThread.start()
			
#This function resends the JOIN request to the Room server in every 20 seconds
#in order to indicate the P2PChat peer is still an active member in that chatroom group.
def keepAliveProcedure():
	global userStatus
	CmdWin.insert(1.0, "\nkeepAliveProcedure")
	while sktToRoomServer:																	#Indicate this P2PChat peer is still an active member
		updateMemberList("keepAliveProcedure")												#Perform JOIN and update membership list		
		if userStatus == "JOINED" or not forwardLink:										#If client is JOINED but not CONNECTED, keep looking for a peer
			global memberList
			findP2PPeer(memberList)
		time.sleep(20)																		#Every 20 seconds

#This function resends the JOIN request to the Room server.
#It also handles the updated membership list.	
def updateMemberList(*src):
	global sktToRoomServer
	global username
	global roomname
	global myIP
	global listeningPort
	global memberList
	global memberListHash 
	msg = "J:"+roomname+":"+username+":"+myIP+":"+listeningPort+"::\r\n"					#Generate JOIN request
	try:
		sktToRoomServer.send(msg.encode("ascii"))
		res = sktToRoomServer.recv(1024)
		res = str(res.decode("ascii"))
		if res:
			if res[0] == 'M':																#Normal message
				now = datetime.datetime.now()												#Get current time
				print(src, " updateMemberList at ", now.strftime("%Y-%m-%d %H:%M:%S"))
				res = res[2:-4]
				mList = res.split(":")
				if memberListHash != mList[0]:												#If the membership list has been changed
					memberListHash = mList[0]												#Update stored hash value
					memberList = []
					for member in chunk(mList[1:], 3):
						memberList.append(member)
					print("Membership list is updated")
					updateMemberHashs(memberList)											#Calculate hash values for each member in the group
				return True
			elif res[0] == 'F':																#Get an error message
				res = res[2:-4]
				CmdWin.insert(1.0, "\nupdateMemberList() JOIN Error")
				return False
		else:
			return False
	#except:
	except ValueError as e:
		raise Exception('Invalid json: {}'.format(e)) from None
		CmdWin.insert(1.0, "\ndo_Join(): Sending message Error")
		if sktToRoomServer:
			sktToRoomServer.close()	
		serverConnectThread=threading.Thread(target=serverConnect, args=(updateMemberList, ))#Start a new thread to make a connection with the room server and call updateMemberList again
		serverConnectThread.setDaemon(True)
		serverConnectThread.start()


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
		memberHashs.append( (member,sdbm_hash(memInfo)) )					#Append ((name, IP, Port), hashID)to the memberHashs array
	memberHashs = sorted(memberHashs, key=lambda tup: tup[1])			#sort the array according to hash IDs
	return myInfo														#Return (name, IP, Port) of the current user
	

#This function set up a TCP socket for the user so that the user could listen to all the incoming messages
def serverProcedure():
	global listeningPort
	sockfd = socket.socket()																#Create a socket
	try:
		sockfd.bind( ('', int(listeningPort)) )	
	except socket.error as emsg:
		print("serverProcedure: Socket bind error: ", emsg)
		sys.exit(1)
	while sockfd:
		sockfd.listen(5)
		conn, address = sockfd.accept()
		msg = conn.recv(1024)				
		msg = str(msg.decode("ascii"))
		
		if msg:
			if msg[0] == 'P':															 	#Receive a P2P handshaking message
				msg = msg[2:-4]												  			 	#Get useful information
				Info = msg.split(":")
				pRoomname = Info[0]
				pUsername = Info[1]
				pIP = Info[2]
				pPort = Info[3]
				pMsgID = Info[4]
				initialPeer = (pUsername, pIP, pPort)										#This is the informaion (name, IP, Port) of the peer who sends the request
				
				global memberList		
				idx = -1	
				try:					
					idx = memberList.index(initialPeer)										#Check whether the peer is in the member list
				except ValueError:															#If we can't find the peer, update the member list
					if updateMemberList("Server Procedure find peer"):		
						try:
							idx = memberList.index(initialPeer)								#Check again
						except ValueError:													#Still can't find the peer
							print("serverProcedure(): Can't find the peer in the member list")
							idx = -1												
							conn.close()													#Close the connection 
					else:
						print("serverProcedure(): Can't update member's list")
						conn.close()
				if idx != -1:
					global msgID
					global backLinks
					global userStatus
					res = "S:"+str(msgID)+"::\r\n"											#Create a message indicating the connection is successful
					conn.send(res.encode("ascii"))											#Reply the peer
					concatInfo = pUsername + pIP + pPort
					backLinks.append(( (initialPeer, sdbm_hash(concatInfo)) ,conn ))		#Add the new peer to its backLinks 
					clientStatus = "CONNECTED"												#Update status to CONNECTED 
		
					try:
						listenPeerThread=threading.Thread(target=listenPeer, args=("Backward", conn, ))				##Start a new thread to listen for messages from client
						listenPeerThread.setDaemon(True)
						listenPeerThread.start()
					except Exception:
						print(traceback.format_exc())

					CmdWin.insert(1.0, "\nAdd " + pUsername + " to backedLink")
			else:
				conn.close()
		else:
			conn.close()

#This function listens the message sent from the peer
#linkType is "Forward" or "Backward"
def listenPeer(linkType, conn):
	while conn:	
		res = conn.recv(1024)																				#Receive the message from the peer
		res = str(res.decode("ascii"))
		if res:									
			if res[0] == 'T':																				#forwarding TEXT message	
				res = res[2:-4]																				#Get all the necessary information
				msgInfo = res.split(":")
				
				tRoomname = msgInfo[0]	
				global roomname
				if tRoomname == roomname:																	#Check whether the message is sent to the correct room	
					originHID = msgInfo[1]
					tUsername = msgInfo[2]
					originMsgID = msgInfo[3]
					msgLength = msgInfo[4]
					msgContent = res[-(int(msgLength)):]													#We use message length in order to take all the message content
					global myLock
					
					myLock.acquire()																		#We acquire a mutex lock before entering the critical section
					global receivedMsg
					global memberList
					if (originHID, originMsgID) not in receivedMsg:											#This is a new message
						receivedMsg.append((originHID, originMsgID))										#Add this message to the received message list
						MsgWin.insert(1.0, "\n["+tUsername+"] "+msgContent)
						myLock.release()																	#Release lock
						forward_Msg(originHID, tUsername, originMsgID, msgContent)							#Forward the message to all connected links
						senderHID = [member for member in memberList if str(member[1]) == str(originHID) ] 
						if not senderHID:																	#update members list
							updateMemberList("listenPeer: didn't find the member's hash")
					else:
						print("listenPeer: The message has been received before")
						myLock.release()
				else:
					print("listenPeer: wrong roomname")
		else:
			CmdWin.insert(1.0, "\n listenPeer: conn break")
			break																							#Connection broken
	#The connection is closed. We need to remove the link
	if linkType == "Forward":																				#If a forward link has been broken, the client is DISCONNECTED, and put back in JOINED state
		CmdWin.insert(1.0, "\n forward link broken")	
		updateMemberList("Forward Link Broken at listenPeer")												#When a forward link is broken, we update the status and forwardLink 
		global forwardLink
		global userStatus
		forwardLink = ()
		userStatus = "JOINED"
		findP2PPeer(memberList)																				#The clent needs to find a new P2P peer
	else:																									#If back link broken, remove the link from backlinks array
		CmdWin.insert(1.0, "\n backward link broken")	
		global backLinks
		for link in backLinks:
			if link[1] == conn:
				backLinks.remove(link)
				break


#This function returns True if P2P handshaking is successful
def handshake(peerSocket):
	global roomname
	global username
	global myIP
	global listeningPort
	global msgID
	msg = "P:"+roomname+":"+username+":"+myIP+":"+listeningPort+":"+str(msgID)+"::\r\n" 					#Create the peer-to-peer handshaking request
	try:
		peerSocket.send(msg.encode("ascii")) 																#Send request to peer
		res = peerSocket.recv(1024)
		res = str(res.decode("ascii"))
		if res:
			if res[0] == 'S':																				#S: successfully connected
				return True
			else:
				CmdWin.insert(1.0, "\nhandshake failed")	
				return False
	except:
		CmdWin.insert(1.0, "\n handshake false: send request faild")	
		return False

#This function try to find a peer and make a TCP connection (forward link) to that peer
def findP2PPeer(memberList):
	global memberHashs
	global backLinks
	global userStatus
	global myHashID
	global forwardLink
	myInfo = updateMemberHashs(memberList)								 							#myInfo is (name, IP, Port) of the current user
	start = memberHashs.index((myInfo, myHashID)) + 1					 							#Use myHashID to find the index X and start = X + 1
	start = start % len(memberHashs)									 							#In case start is larger than the length of memberHashs 

	while memberHashs[start][1] != myHashID:							 							#Loop until reach the user 
		
		if [link for link in backLinks if link[0] == memberHashs[start]]:							#There is an existing backward link between the user and the current peer
			start = (start+1) % len(memberHashs)					     							#Wrap around if reaching the end
			continue
		else:																						#We find a peer to connect
			forwardSkt = socket.socket() 
			try:
				peerIP = memberHashs[start][0][1]		
				peerPort = int(memberHashs[start][0][2])		
				forwardSkt.connect((peerIP, peerPort))
			except:
				print("findP2PPeer: establish TCP connection with "+str(peerIP)+" "+str(peerPort)+" failed")
				start = (start + 1) % len(memberHashs) 
				continue
			if forwardSkt:																			#Establish TCP connection 
				if handshake(forwardSkt):															#P2PHandShake successfully
					userStatus = "CONNECTED"														#Set up a connection successfully. Update user status
					forwardLink = (memberHashs[start], forwardSkt)									#((name, IP, Port), forwardSkt)
					try:
						listenPeerThread=threading.Thread(target=listenPeer, args=("Forward", forwardSkt, ))#Start a new thread to listen for messages from client
						listenPeerThread.setDaemon(True)
						listenPeerThread.start()
					except Exception:
						print(traceback.format_exc())

					CmdWin.insert(1.0, "\nforward linked to " + memberHashs[start][0][0])			#If success, store connection
					break
				else:
					forwardSkt.close()																#Try another peer
					start = (start+1) % len(memberHashs)
					continue			
			else:
				forwardSkt.close()																	#Try another peer
				start = (start+1) % len(memberHashs)
				continue
	if userStatus != "CONNECTED":																	#After the while loop, the user is still not connected
		print("findP2PPeer: Cannot find a forward P2P peer")


#This function sends a message to the linked peers. 
#The user is the original sender 
def do_Send():
	if userentry.get(): #Check whether there is input
		message = userentry.get()
		global userStatus
		if userStatus == "JOINED" or userStatus == "CONNECTED":
			global msgID
			global username
			global myHashID
			msgID += 1	#Update the message ID
			forward_Msg(myHashID, username, msgID, message)#Send message
			MsgWin.insert(1.0, "\n["+username+"] "+message)
		else:
			CmdWin.insert(1.0, "\ndo_Send(): The user hasn't joined a chatroom or not connected")
	userentry.delete(0, END)

#This function forwards the message to the linked peers
#The user may not be the original sender
def forward_Msg(originHID, originUsername, msgID, message):
	global roomname
	global forwardLink
	global backLinks
	msg = "T:"+roomname+":"+str(originHID)+":"+originUsername+":"+str(msgID)+":"+str(len(message))+":"+message+"::\r\n"			#Create the message
	if forwardLink:										
		if str(forwardLink[0][1]) != str(originHID):				#Make sure the forward link is not the original sender
			forwardLink[1].send(msg.encode("ascii"))				#Send message
	for link in backLinks:					
		if str(link[0][1]) != str(originHID):						#Make sure the backward link is not the original sender
			link[1].send(msg.encode("ascii"))		

#This class listens to Poke message
class theListenThread(threading.Thread): 
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
				udp_client_ip = udp_client_pair[1]
				udp_client_name = udp_client_msg.split("::")[0].split(':')[2]
				CmdWin.insert(1.0, "\nReceived a poke from " + udp_client_name)
				MsgWin.insert(1.0, "\nYou are poked by [" + udp_client_name+ "] ")
				udp_socket.sendto(udp_respond.encode("ascii"), udp_client_ip) #send reply



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
						exist=False
						addressOfPeer=member[1]
						portOfPeer=member[2]
		
						sockPoke=socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 	#create a UDP socket
						sockPoke.sendto(msg.encode("ascii"), (addressOfPeer, int(portOfPeer)))
						CmdWin.insert(1.0, "\nA Poke has been sent successfully to "+nickname)
						
						sockPoke.settimeout(2) 										#set 2s timeout
						try:
							udp_server_respond = sockPoke.recv(1024).decode("ascii")
							MsgWin.insert(1.0, "\nYou poked [" + nickname+ "] successfully")
							CmdWin.insert(1.0, "\nACK Received from "+ nickname)
						except socket.timeout as e:
							CmdWin.insert(1.0, "\nTime out!")
			if exist:
				CmdWin.insert(1.0, "\nError: "+nickname+" is not in the chatroom!")
		
		else:																		#print all pees in the room if there's no nickname input
			for member in memberList:
				CmdWin.insert(1.0, "\n"+member[0])
			CmdWin.insert(1.0, "\nTo Whom do you want to send the Poke?")
		
		
		
	if userStatus != "JOINED" and userStatus != "CONNECTED": 
		CmdWin.insert(1.0, "\nError: You should join a chatroom first!")


#This function closes all the sockets and exit the program.
def do_Quit():
	global sktToRoomServer
	global forwardLink
	global backLinks
	#Close socket to the room server, to forward link and to all the backlinked clients.
	if sktToRoomServer:
		sktToRoomServer.close()
		print("do_Quit(): Closed Socket to room server")
	if forwardLink:
		forwardLink[1].close()
		print("Quit: Closed Socket to Forward link")
	for back in backLinks:
		back[1].close()
		print("Quit: Closed Socket to Backward link")
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

		serverConnectThread=threading.Thread(target=serverConnect, args=(do_User,)) #Create a new thread for connecting server
		serverConnectThread.setDaemon(True)
		serverConnectThread.start()

	win.mainloop()

def serverConnect(callback):
	global sktToRoomServer
	global serverIP
	global serverPort
	global myIP
	
	try:
		sktToRoomServer = socket.socket()
		sktToRoomServer.connect((serverIP, int(serverPort)))
		myIP = sktToRoomServer.getsockname()[0]
		CmdWin.insert(1.0, "\nserverConnect(): Successful")
	except socket.error as emsg:
		CmdWin.insert(1.0, "\nserverConnect(): Connecting to Server Error")
		sys.exit(1)
	callback()

if __name__ == "__main__":
	main()

