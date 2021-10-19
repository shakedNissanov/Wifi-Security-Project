from datetime import datetime
from scapy.all import *
import random
import multiprocessing
import time
import sys
import argparse

from probeAttack import *
from beaconAttack import *
from authenticationAttack import *

def handleArguments():
	parser = argparse.ArgumentParser(description='A fuzzer designed to fuzz different stages of the wifi connection process.')
	parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
	parser.add_argument("-t", "--target", help="choose a target to fuzz using a mac address")
	parser.add_argument("-s", "--source", help="choose what the source mac address of the packets will be")
	parser.add_argument("-i", "--interface", help="choose which interface to use", default="wlan0")
	parser.add_argument("--secured", help="make the wifi network created secured by a password", default=False, action="store_true")
	parser.add_argument("-preq", "--probe-using-request", help="try fuzzing probe responses using a sniffed request from the target", action="store_true")
	parser.add_argument("-pres", "--probe-using-response", help="try fuzzing probe responses using a sniffed response to the target", action="store_true")
	parser.add_argument("--beacon", help="try fuzzing beacon frames", action="store_true")
	parser.add_argument("--auth", help="INCOMPLETE - try fuzzing the authentication stage", action="store_true")
	args = parser.parse_args()

	if not args.probe_using_request and not args.probe_using_response and not args.beacon and not args.auth:
		parser.error("You must choose an attack")
		exit(1)
	if not args.target or not args.source:
		parser.error("You must choose a target and a source")
		exit(1)
	return args
		
def main():
	args = handleArguments()
	name = input("Choose the ssid of the network you will advertize: ")
	length = int(input("Choose the length of the ssid that will be shown to the device: "))

	print('\n' + 'Attacker Initialized')
	print('Attacking the target: ' + args.target + '\n')

	if(args.probe_using_request):
		ProbeAttack(name, length, args.secured, args.verbose, args.target, args.source, args.interface, args.interface).probeAttackUsingRequest()
	elif(args.probe_using_response):
		ProbeAttack(name, length, args.secured, args.verbose, args.target, args.source, args.interface, args.interface).probeAttackUsingSniffedResponse()
	elif(args.beacon):
		BeaconAttack(name, length, args.secured, args.verbose, args.target, args.source, args.interface, args.interface).beaconAttack()
	elif(args.auth):
		AuthenticationAttack(name, length, args.secured, args.verbose, args.target, args.source, args.interface, args.interface).authenticationAttack()
	
if __name__ == '__main__':
	main()
