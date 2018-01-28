## This software is licensed under the MIT License - please refer to the LICENCE file for details

# Copyright (c) 2018 Stephane Teisserenc

***************************************************************************************************************************
Installation
***************************************************************************************************************************
install python 3 and pip

install with pip: pip install pyxpudpserver (you may need to use pip3 rather than pip)

***************************************************************************************************************************
Description
***************************************************************************************************************************
Python module that allows to communicate with XPlane via UDP: Set/receive datarefs, send commands; The class can also be set up to forward XPlane UDP traffic to other devices on the network, and/or redirect traffic from these devices to XPlane.
When importing the module, an instance of the class is created called pyXPUDPServer.
This instance needs to be initialised by calling the initialiseUDP() or initialiseUDPXMLConfig() method, and the thread can be started by calling start().

The class is inherited from the Threading module, and will run as its own thread when started.
The class will keep track of the status of the connectivity with XPlane; if it is interrupted, it will re connect to XPlane when it comes back online, and re subscribe any datarefs.
You need to call the quit() method when exiting the programme.

***************************************************************************************************************************
Simple Example:
***************************************************************************************************************************
@code

import pyxpudpserver as XPUDP

XPUDP.pyXPUDPServer.initialiseUDP(('127.0.0.1',49008), ('192.168.1.1',49000), 'MYPC')

# where ('127.0.0.1',49008) is the IP and port this class is listening on (configure in the Net connections in XPlane)

# and ('192.168.1.1',49000) is the IP and port of XPlane

# 'MYPC' is the name of the computer XPlane is running on

# You can also initialise from an XML configuration file:

XPUDP.pyXPUDPServer.initialiseUDPXMLConfig('UDPSettings.xml')

XPUDP.pyXPUDPServer.start() # start the server which will run an infinite loop

while True: # infinite loop - for a real application plan for a 'proper' way to exit the programme and break this loop

  value = XPUDP.pyXPUDPServer.getData((17,3)) 	# read the value sent by XPlane for datagroup 17, position 4 (mag heading)
 	
  transp_mode = XPUDP.pyXPUDPServer.getData("sim/cockpit2/radios/actuators/transponder_mode[0]") # gets the value of this dataref in XPlane

XPUDP.pyXPUDPServer.sendXPCmd('sim/engines/engage_starters') # send command to XPlane to engage the engine starters

XPUDP.pyXPUDPServer.sendXPDref("sim/flightmodel/controls/flaprqst", 0, value = 0.5) # set the requested flap deployment to 0.5 - bear in mind the flap will then deploy and take some time to do so - monitor its actual position if needed

XPUDP.pyXPUDPServer.quit() # exit the server thread and close the sockets

@endcode
