## This software is licensed under the MIT License - please refer to the LICENCE file for details
#
# Copyright (c) 2018 Stephane Teisserenc
#

import sys, threading
import socket
import logging
import time
from struct import *
import xml.etree.ElementTree as ET

logger = logging.getLogger('UDPserver')

## Python class that allows to communicate with XPlane via UDP: Set/receive datarefs, send commands; The class can also be set up to forward XPlane UDP traffic to other devices on the network, and/or redirect traffic from these devices to XPlane.
# When importing the module, an instance of the class is created called pyXPUDPServer.
# This instance needs to be initialised by calling the initialiseUDP() or initialiseUDPXMLConfig() method, and the thread can be started by calling start().
#
# The class is inherited from the Threading module, and will run as its own thread when started.
# The class will keep track of the status of the connectivity with XPlane; if it is interrupted, it will re connect to XPlane when it comes back online, and re subscribe any datarefs.
# You need to call the quit() method when exiting the programme.
# Simple Example:
#
# @code
# import pyxpudpserver as XPUDP
# XPUDP.pyXPUDPServer.initialiseUDP(('127.0.0.1',49008), ('192.168.1.1',49000), 'MYPC')
# # where ('127.0.0.1',49008) is the IP and port this class is listening on (configure in the Net connections in XPlane)
# # and ('192.168.1.1',49000) is the IP and port of XPlane
# # 'MYPC' is the name of the computer XPlane is running on
# # You can also initialise from an XML configuration file:
# XPUDP.pyXPUDPServer.initialiseUDPXMLConfig('UDPSettings.xml')
#
# XPUDP.pyXPUDPServer.start() # start the server which will run an infinite loop
#
# while True: # infinite loop - for a real application plan for a 'proper' way to exit the programme and break this loop
# 	value = XPUDP.pyXPUDPServer.getData((17,3)) 	# read the value sent by XPlane for datagroup 17, position 4 (mag heading)
# 	transp_mode = XPUDP.pyXPUDPServer.getData("sim/cockpit2/radios/actuators/transponder_mode[0]") # gets the value of this dataref in XPlane
#
#	XPUDP.pyXPUDPServer.sendXPCmd('sim/engines/engage_starters') # send command to XPlane to engage the engine starters
#	XPUDP.pyXPUDPServer.sendXPDref("sim/flightmodel/controls/flaprqst", 0, value = 0.5) # set the requested flap deployment to 0.5 - bear in mind the flap will then deploy and take some time to do so - monitor its actual position if needed
#
# XPUDP.pyXPUDPServer.quit() # exit the server thread and close the sockets
#
# @endcode
#

PYTHON_VERSION = sys.version_info[0]

class XPlaneUDPServer(threading.Thread):

	## constructor
	# @param Address: tuple of IP address, UDP port we are listening on
	#
	def __init__(self):
		threading.Thread.__init__(self)
		self.running = True
		self.updatingRREFdict = False
		self.statusMsg = "Not connected"

		self.XPbeacon = {
			'beacon_major_version'	: None,
			'beacon_minor_version'	: None,
			'application_host_id'	: None,
			'version_number'		: None,
			'role'					: None,
			'port'					: None,
			'computer_name' 		: None
		}

		self.MCAST_GRP = '239.255.1.1'
		self.MCAST_PORT = 49707

		# socket listening to XPlane Data
		self.XplaneRCVsock = None
		self.forwardXPDataAddresses = [] # default the forward addresses to empty list
		self.XPCmd_Callback_Functions = [] # list of callback functions to be called when the class is asked to send a command to XPlane

		self.RDRCT_TRAFFIC = False # by default we do not redirect incoming traffic to Xplane
		self.DataRCVsock = False
		self.XPAddress = None
		self.XPComputerName = None

		# socket to send data
		self.sendSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

		self.RREF_sockets = [] # list to store RREF sockets, one for each dataref subscribed. Not very elegant, but XPlane does not seem to be able to deal with multiple RREF requests from the same socket
		self.datarefsDict = {} # dictionary to store dataref values received from XP
		self.datarefsIndices = {}

		self.dataList =[] # list to store the Data Set values received from XP as configured in the Data Input & Output screen
		self.cmddata = None
		for i in range(0,1024) :
			self.dataList.append([0,0,0,0,0,0,0,0]) # initialise the dataList with 0 values

		self.continuousXPCommandsQueue = []


	## Initialise the UDP sockets to communicate with XPlane
	# @param Address: tuple of IP address (str), UDP port (int) we are listening on
	# @param XPAddress: tuple of IP address (str), UDP port (int) for XPlane
	# @param XPComputerName: Network name of the computer XPlane is running on
	#
	def initialiseUDP(self, Address, XPAddress, XPComputerName):
		logger.info("Initialising XPlaneUDPServer on address: %s", Address)
		# socket listening to XPlane Data
		try:
			self.XplaneRCVsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.XplaneRCVsock.setblocking(0)
			self.XplaneRCVsock.bind(Address) # bind this socket to listen to traffic from XPlane on the address passed to the constructor
			self.XPAddress = XPAddress
			self.XPComputerName = XPComputerName
			self.XPalive = True

			self.mcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
			self.mcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.mcast_sock.bind(('', self.MCAST_PORT))  # use MCAST_GRP instead of '' to listen only
													# to MCAST_GRP, not all groups on MCAST_PORT
			mreq = pack("4sl", socket.inet_aton(self.MCAST_GRP), socket.INADDR_ANY)

			self.mcast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
			self.mcast_sock.setblocking(0)
		except:
			logger.error('Error while starting UDP server', exc_info=True)

	## Initialise the UDP sockets to communicate with XPlane
	# @param XMLConfigFile: relative path to XML config file
	#
	def initialiseUDPXMLConfig(self, XMLConfigFile):
		self.ardXMLconfigFile = XMLConfigFile
		self.tree = ET.parse(self.ardXMLconfigFile)
		self.root = self.tree.getroot()

		IPTag = self.root.findall(".//IP")
		XPIPTag = self.root.findall(".//XPIP")
		XPCompNameTag = self.root.findall(".//XPComputerName")
		RedirectUDPtrafficTag = self.root.findall(".//RedirectUDPtraffic")
		IPRedirectTag = self.root.findall(".//RedirectIP")
		ForwardIPAddressesTag = self.root.findall(".//ForwardIPAddresses")
		ForwardIPAddressesTags = ForwardIPAddressesTag[0].findall(".//IP")

		try:
			Address = (IPTag[0].attrib['address'], int(IPTag[0].attrib['port']))
			XPAddress = (XPIPTag[0].attrib['address'], int(XPIPTag[0].attrib['port']))
			XPComputerName = XPCompNameTag[0].attrib['network_name']

			self.initialiseUDP( Address, XPAddress, XPComputerName)

			state = RedirectUDPtrafficTag[0].attrib['state']
			if state == 'True':
				pass#self.XP_RedirectTraffic_checkBox.setChecked(True)
				RedIPAddress = (IPRedirectTag[0].attrib['address'], int(IPRedirectTag[0].attrib['port']))
				self.enableRedirectUDPtoXP(RedIPAddress, XPAddress)
				logger.info('Set redirection of traffic received to XP on address'+str(RedIPAddress))

			fwdIPAdresses = []
			if len(ForwardIPAddressesTags) > 0:
				for forwardIPtag in ForwardIPAddressesTags:
					address = forwardIPtag.attrib['address']
					port = forwardIPtag.attrib['port']

					if address != '' and port != '':
						fwdIPAdresses.append((address,int(port)))
			logger.info('setting fwd IP addresses to:'+str(fwdIPAdresses))
			self.enableForwardXPpackets(fwdIPAdresses)

		except:
			logger.error('error while retrieving xml data', exc_info=True)

	## Enables the redirection of traffic received by the class to XPlane
	# @param myAddress: The address the class is listening for traffic on. Format: (IP,port)
	# @param XPAddress: The XP address we will be forwarding the packets to. Format: (IP, port)
	#
	def enableRedirectUDPtoXP(self, myAddress, XPAddress):
		try:
			self.RDRCT_TRAFFIC = True
			self.XPAddress = XPAddress
			self.DataRCVsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.DataRCVsock.setblocking(0)
			self.DataRCVsock.bind(myAddress)
		except:
			self.RDRCT_TRAFFIC = False
			logger.error('Error opening redirection socket ', exc_info=True )

	## Disables the redirection of traffic received by the class to XPlane
	#
	def disableRedirectUDPtoXP(self):
		self.RDRCT_TRAFFIC = False
		try:
			self.DataRCVsock.close()
		except:
			logger.error('Error closing redirect socket ', exc_info=True )

	## Enables the forwarding of data received from XPLane to a list of IP addresses
	# @param forwardAddresses: a list of addresses to forward to, in the format [(IP1,port1),(IP2,port2), ... ]
	#
	def enableForwardXPpackets(self,forwardAddresses):
		self.forwardXPDataAddresses = forwardAddresses

	## Returns data last received from XPlane for the key, index provided.
	# @param dataReference: This can be either a tuple if requesting data set up in the Data Input&Output screen in XPlane, or a string if requesting data from a dataref. The method will automatically request XP to send the dataref if it has not been done previously.
	#	getData("sim/cockpit2/radios/actuators/transponder_mode[0]")
	def getData(self,dataReference):
		strobject = str
		if PYTHON_VERSION == 2: strobject = basestring

		if isinstance(dataReference, tuple): # then we need to return data from dataList
			if dataReference[0] >= 0 and dataReference[0] <1024:
				return self.dataList[dataReference[0]] [dataReference[1]]
			else:
				return 0.0

		elif isinstance(dataReference, strobject): # then we have a dataref - this works with python 3 only.
			if dataReference in self.datarefsDict: # that dataref has already been requested so return the value
				return self.datarefsDict[dataReference]
				logger.debug(self.datarefsDict)
			else: # this dataref has not been requested so let's request it, and return 0.0 for this time
				#logger.debug("dataref not previously requested %s", dataReference)
				self.requestXPDref(dataReference)
				return 0.0

		else: # then we have been passed rubbish
			logger.error("can not recognise the type of dataReference")
			return 0.0

	## Prints data to the console for the key, index provided.
	# @param dataReference: This can be either a tuple if requesting data set up in the Data Input&Output screen in XPlane, or a string if requesting data from a dataref. The method will automatically request XP to send the dataref if it has not been done previously.
	#
	def printData(self,dataReference):
		if key >= 0 and key <1024:
			print ("Data Group: ", key, " [",self.dataList[key][0],",",self.dataList[key][1],",",self.dataList[key][2],",",self.dataList[key][3],",",self.dataList[key][4],",",self.dataList[key][5],",",self.dataList[key][6],",",self.dataList[key][7],"]")
		else:
			logger.error ( "Invalid key")


	## Request Dataref from XPlane - note calling getData('somedataref') will achieve the same effect and might be easier (will call this function in the background)
	# @param string for the dataref to be requested from XPlane - refer to the XPlane doc for a list of available datarefs
	#
	def requestXPDref(self, dataref):
		self.updatingRREFdict = True

		if self.XPAddress is not None: # check if we have XPlane's IP, if so continue, else log an error
			if dataref in self.datarefsDict: #  if the dataref has already been requested, then return, no need to do anything
				logger.debug("dataref has already been requested")
				return
			else:
				logger.debug("Requesting dataref %s", dataref)
				self.datarefsDict[dataref] = 0.0	# initialise a new key for this dataref
				index = len(self.datarefsDict)-1	# give it an index
				self.datarefsIndices[index] = ['',None]
				self.datarefsIndices[index][0] = dataref

				RREF_Sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				#RREF_Sock.setblocking(0)
				self.datarefsIndices[index][1] = RREF_Sock

				logger.debug("datarefs Dict: %s", self.datarefsDict)
				logger.debug("datarefs Indices: %s", self.datarefsIndices)

				self.RREF_sockets.append(RREF_Sock)

				self.__sendRREFmessage(index)
		self.updatingRREFdict = False

	## private - format and send an RREF message to XP
	#
	def __sendRREFmessage(self, index):
		if self.XPAddress is not None:
			dataref = self.datarefsIndices[index][0]

			dataref+= '\0'
			nr_trailing_spaces = 400-len(dataref)

			msg = "RREF"+'\0'
			packedindex = pack('<i', index)
			packedfrequency = pack('<i', 30)
			msg += packedfrequency.decode(encoding = 'latin_1')
			msg += packedindex.decode(encoding = 'latin_1')
			msg += dataref
			msg += ' '*nr_trailing_spaces

			logger.debug("Requesting DataRef, RREF msg: %s", msg)
			self.datarefsIndices[index][1].sendto(msg.encode('latin_1'), self.XPAddress)
			self.datarefsIndices[index][1].setblocking(0)

		else:
			logger.error("XPlane IP address undefined")

	## private - attempt to re subscribe all the RREFs previously subscribed (if XPlane was restarted for example)
	#
	def __resubscribeRREFs(self):
		if len(self.datarefsIndices) > 0 and self.updatingRREFdict == False:
			logger.info("Attempt to re subscribe datarefs with XPlane")
			if PYTHON_VERSION == 2:
				for index, RREF in self.datarefsIndices.iteritems():
					self.__sendRREFmessage(index)
			else:
				for index, RREF in self.datarefsIndices.items():
					self.__sendRREFmessage(index)

	## send command to XPlane
	# @param string for the command to be sent to XPlane - refer to the XPlane doc for a list of available commands
	# @param sendContinuous		default False, command will only be sent once. If True, the command will be sent continuously until a call to stopSendingXPCmd is made
	def sendXPCmd(self, command, sendContinuous = False):
		if self.XPAddress is not None and command is not None:
			msg = 'CMND0'
			msg += command

			self.sendSock.sendto(msg.encode("latin_1"), self.XPAddress)
			logger.debug('sent XP command : '+msg )
			if sendContinuous == True:
				# let's make sure this command is not in the queue already
				matching_cmds = [cmd for cmd in self.continuousXPCommandsQueue if (cmd == command) ]
				if len(matching_cmds) == 0: # if its not then lets add it
					self.continuousXPCommandsQueue.append(msg)

			for callback in self.XPCmd_Callback_Functions:
				callback(command)
		else:
			logger.error("XPlane IP address undefined")


	def stopSendingXPCmd(self, command):
		command = 'CMND0' + command
		try:
			self.continuousXPCommandsQueue.remove(command)
		except:
			logger.debug('Error removing command from continuous commands queue', exc_info=True)


	## send Dataref to XPlane
	# @param string for the dataref to be sent to XPlane - refer to the XPlane doc for a list of available datarefs
	# format of dataref string should be 4 bytes (chars) for the value to set, followed by the dataref path, then by a null character. The function will automatically pad white spaces to the length XPlane expects
	#
	def sendXPDref(self, dataref):
		if self.XPAddress is not None:
			nr_trailing_spaces = 504-len(dataref)

			msg = 'DREF0'+dataref
			msg += ' '*nr_trailing_spaces
			if len(msg) == 509:
				self.sendSock.sendto(msg.encode("latin_1"), self.XPAddress)
		else:
			logger.error("XPlane IP address undefined")

	## send Dataref to XPlane
	# @param dataref string for the dataref to be sent to XPlane - refer to the XPlane doc for a list of available datarefs
	# @param index the index - for datarefs that have multiple values, default 0
	# @param value - the value to set the dataref to
	#
	def sendXPDref(self, dataref, index = 0, value = 0.0):
		logger.debug('sending DREF'+dataref)

		if self.XPAddress is not None:
			val = float(value)

			dataref += '['+str(index)+']'

			bytesval = pack('<f',val)
			nr_trailing_spaces = 500-len(dataref)

			msg = 'DREF0'.encode("latin_1")+bytesval+dataref.encode("latin_1")
			msg += ' '.encode("latin_1")*nr_trailing_spaces
			#logger.debug('UDP message: ' + msg.decode())
			if len(msg) == 509:
				logger.debug('sending UDP message: ' )

				self.sendSock.sendto(msg, self.XPAddress)
		else:
			logger.error("XPlane IP address undefined")

	## registers a callback function to be called if the class receives a sendXPCmd() call
	# @param callback - the callback function, it will be given the command string as parameter so your callback must handle the command string
	#
	def registerXPCmdCallback(self, callback):
		self.XPCmd_Callback_Functions.append(callback)


	## Internal thread loop - Do not call - use the start() method to start the thread, which will call run()
	# infinite loop listening for data from XPlane. When data is received, it is parsed and stored/updated in the
	# dataList attribute
	# If the instance has been configured to forward XPlane packets, it will loop through the forward addresses to do so
	# If the instance has been configured to re direct traffic to XPlane, it will forward any packets received to XP
	#
	def run(self):
		lasttimeXPbeaconreceived = time.time()

		while self.running:
			current_time = time.time()

			##---------------------------------------------------
			#	check XPlane beacon
			##---------------------------------------------------
			try:
				(msg, address) = self.mcast_sock.recvfrom(10240)
				#logger.debug('received beacon from address '+str(address))
				self.__parseXplaneBeaconPacket(msg)
				if self.XPbeacon['computer_name'] == self.XPComputerName and address[0] == self.XPAddress[0]: # it seems the XPlane instance we are trying to communicate with is alive
					lasttimeXPbeaconreceived = current_time
					if self.XPalive == False: # if xplane was down it is now back up again, lets try and re subscribe the datarefs
						self.__resubscribeRREFs()
					self.XPalive = True
					self.statusMsg = "Connected to XPlane running on computer: "+self.XPComputerName + ", IP: "+str(address[0]) + ", Version: "+ str(self.XPbeacon['version_number'])

			except socket.error as msg: pass

			elapsed_time_since_beacon_rcvd = current_time - lasttimeXPbeaconreceived
			if elapsed_time_since_beacon_rcvd >= 2.5: #we have not received data from Xplane for a while
				#logger.debug("Not received XPlane beacon for %s seconds", elapsed_time_since_beacon_rcvd)
				self.XPalive = False
				self.statusMsg = "Not connected to XPlane, last message received "+"{0:.0f}".format(elapsed_time_since_beacon_rcvd)+" seconds ago"

			##---------------------------------------------------
			#	Process incoming XPlane UDP data
			##---------------------------------------------------
			try:
				#print ("xp server atttempt to receive data...")
				data, addr = self.XplaneRCVsock.recvfrom(8192) # receive data from XPlane

				fwddata = data
				#print(data)
				#print(data[0:4])
				if data[0:4].decode('ascii') == "DATA":
					#print("Received XP data")
					self.__parseXplaneDataPacket(data)

				if len(self.forwardXPDataAddresses) > 0: # loop through forward addresses and send fwd_data packet
					for i in range(0,len(self.forwardXPDataAddresses)) :
						#if self.forwardXPDataAddresses[i][1] == True:
						self.sendSock.sendto(fwddata,self.forwardXPDataAddresses[i])
						#else :
						#	if data[0:5].decode('ascii') != "DATA|":
						#		self.sendSock.sendto(fwddata,self.forwardXPDataAddresses[i][0])

			except socket.error as msg: pass
				#print ("UDP Xplane receive error code ", str(msg[0]), " Message: ", str(msg[1]) )

			##---------------------------------------------------
			#	Process incoming RREF dataref data
			##---------------------------------------------------
			try:
				if self.updatingRREFdict == False: # to avoid having issues with dictionary iteration

					for index, RREF in self.datarefsIndices.items():
						dataref = RREF[0]
						rrefdata, rrefaddr = self.datarefsIndices[index][1].recvfrom(8192)

						if rrefdata[0:4].decode('ascii') == 'RREF':
							index = unpack('<i', rrefdata[5:9])[0]
							value = unpack('<f', rrefdata[9:13])[0]

							self.datarefsDict[dataref] = value

			except socket.error as msg: pass

			##---------------------------------------------------
			#	Send continuous XP Commands
			##---------------------------------------------------
			if self.XPAddress is not None :
				for cmd in self.continuousXPCommandsQueue:
					self.sendSock.sendto(cmd.encode("latin_1"), self.XPAddress)
					#logger.debug('sent XP command : '+cmd )

					self.statusMsg += ' || '+str(self.continuousXPCommandsQueue)

					for callback in self.XPCmd_Callback_Functions:
						callback(cmd)
			else:
				logger.error("XPlane IP address undefined")


			##---------------------------------------------------
			#	Redirect received traffic to XP if required
			##---------------------------------------------------
			if self.RDRCT_TRAFFIC == True:
				try:
					ardData,ardAddr = self.DataRCVsock.recvfrom(8192) # receive data from another source
					#print "Rcvd Data from ", ardAddr, "data: ", ardData[0:6]
					self.sendSock.sendto(ardData, self.XPAddress) # forward it to XPlane
				except socket.error as msg: pass
					#print "UDP ARD receive error code ", str(msg[0]), " Message: ", str(msg[1])


			time.sleep(0.01)

	def __closeSockets(self):
		try:
			self.XplaneRCVsock.close()
			self.mcast_sock.close()
			if self.DataRCVsock != False:
				self.DataRCVsock.close()

		except:
			logger.error('Error while closing UDP server', exc_info=True)

	## restart the UDP sockets to communicate with XPlane
	# @param Address: tuple of IP address (str), UDP port we are listening on (int)
	# @param XPAddress: tuple of IP address (str), UDP port for XPlane (int)
	# @param XPComputerName: Network name of the computer XPlane is running on
	#
	def restart(self, Address, XPAddress, XPComputerName):
		self.__closeSockets()
		self.initialiseUDP(Address, XPAddress, XPComputerName)


	## Call to stop the thread and close the UDP sockets
	#
	def quit(self):
		self.running = False
		self.__closeSockets()

		for index, RREF in self.datarefsIndices.items():
			self.datarefsIndices[index][1].close()
		logger.info("UDP Server stopped...")

	## Internal method that parses a 'BECN' type packet received from XPlane
	# @param packet: The UDP packet to parse
	#
	def __parseXplaneBeaconPacket(self, packet):
		if packet[0:4].decode('ascii') == "BECN" :
			self.XPbeacon['beacon_major_version']	= packet[5]
			self.XPbeacon['beacon_minor_version']	= packet[6]
			self.XPbeacon['application_host_id']	= unpack('<i', packet[7:11])[0]
			self.XPbeacon['version_number']			= unpack('<i', packet[11:15])[0]
			self.XPbeacon['role']					= unpack('<I', packet[15:19])[0]
			self.XPbeacon['port']					= unpack('<H', packet[19:21])[0]
			self.XPbeacon['computer_name']			= packet[21:len(packet)-1].decode('ascii')

			#logger.debug (str(self.XPbeacon))


	## Internal method that parses a 'DATA' type packet received from XPlane
	# it splits the packet into each data group, and calls the parseXPlaneDataGroup method to parse the dataGroup
	# @param packet: The UDP packet to parse
	#
	def __parseXplaneDataPacket(self, packet):
		indexType = "XPUDP"
		if packet[0:5].decode('ascii') == "DATA|" :
			indexType ="STUDP"

		dataGroups = packet[5:len(packet)]
		#print (len(dataGroups))
		if len(dataGroups)%36 != 0 :
			print ("Invalid XPlane DATA packet")
			#print "packet: ", dataGroups
			return
		else :
			nrGroups =  int(len(dataGroups)/36)
			#print ("Number of groups: ", nrGroups)

			for i in range(0,nrGroups) :
				self.__parseXPlaneDataGroup(dataGroups[i*36:i*36+36], indexType)

	## Internal method that parses a Data group and stores it into the dataLIst attribute
	# @param dataGroup: The data group to parse
	#
	def __parseXPlaneDataGroup(self,dataGroup,indexType) :
		if indexType == "XPUDP":
			index = unpack('B',dataGroup[0:1])[0]
		if indexType == "STUDP":
			index = unpack('<i',dataGroup[0:4])[0]
		#print "UDP server - parse Group, index: ", index

		if (index >= 0) and (index <=1024):

			value1 = unpack('<f', dataGroup[4:8])[0]
			value2 = unpack('<f', dataGroup[8:12])[0]
			value3 = unpack('<f', dataGroup[12:16])[0]
			value4 = unpack('<f', dataGroup[16:20])[0]
			value5 = unpack('<f', dataGroup[20:24])[0]
			value6 = unpack('<f', dataGroup[24:28])[0]
			value7 = unpack('<f', dataGroup[28:32])[0]
			value8 = unpack('<f', dataGroup[32:36])[0]

			self.dataList[index] = [value1,value2,value3,value4,value5,value6,value7,value8]
		else:
			pass
			#print("Invalid data index!", index, " Data packet type: ", indexType, "Data group:", dataGroup)

		#logger.debug ("DATA Index: "+ str(index)+ "Value1: "+ str(value1)+ "Value2: "+ str(value2)+ "Value3: " + str(value3)+ "Value4: "+ str(value4))
