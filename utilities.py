from scapy.all import *

def removeEltLayer(pkt, ID):
	layer = pkt.getlayer(Dot11Elt) # get first elt layer
	while layer:
		if(layer.ID == ID): # search using ID
			afterLayer = layer.payload # get everything after the requested elt layer
			layer.underlayer.remove_payload() # remove everything after and including the elt layer
			pkt = pkt / afterLayer # add everything after the elt layer back to effectively delete it
			break
		layer = layer.payload.getlayer(Dot11Elt) # iterate over the elt layers until it finds the one requested
	return pkt
