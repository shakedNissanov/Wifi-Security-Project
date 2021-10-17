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

monitor = "wlan0"
injector = "wlan0"
targetDict = {'shakedPhone' : '6C:C7:EC:BA:E9:22', 'shakedTablet' : '8C:83:E1:F4:16:EC', 'shakedLaptop' : '00:F4:8D:B7:7C:F9', 'shakedKindle' : '4C:17:44:EC:32:ED',
'ellaPhone' : 'DC:0C:5C:B0:D7:36', 'ellaLaptop' : '44:85:00:1C:3A:0E', 'nexus5' : '2C:59:8A:52:04:4C', 'LG_G2' : 'CC:FA:00:CB:12:53',
'onePlus' : 'C0:EE:FB:33:00:FE', 'galaxyTab3' : '20:D3:90:EB:55:77'}
target = targetDict['shakedPhone']
source = "00:0c:29:52:66:4e"

isVerbose = False

def handleArguments():
	global isVerbose
	global target
	global source
	global monitor
	global injector

	parser = argparse.ArgumentParser(description='A fuzzer designed to fuzz different stages of the wifi connection process.')
	parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
	parser.add_argument("-t", "--target", help="choose a target to fuzz using a mac address", default=target)
	parser.add_argument("-s", "--source", help="choose what the source mac address of the packets will be", default=source)
	parser.add_argument("-i", "--interface", help="choose which interface to use", default="wlan0")
	parser.add_argument("--secured", help="make the wifi network created secured by a password", default=False, action="store_true")
	parser.add_argument("-preq", "--probe-using-request", help="try fuzzing probe responses using a sniffed request from the target", action="store_true")
	parser.add_argument("-pres", "--probe-using-response", help="try fuzzing probe responses using a sniffed response to the target", action="store_true")
	parser.add_argument("--beacon", help="try fuzzing beacon frames", action="store_true")
	parser.add_argument("--auth", help="INCOMPLETE - try fuzzing the authentication stage", action="store_true")
	args = parser.parse_args()

	if(not args.probe_using_request and not args.probe_using_response and not args.beacon and not args.auth):
		parser.error("You must choose an attack")
		exit(1)
	isVerbose = args.verbose
	target = args.target
	source = args.source
	monitor, injector = args.interface, args.interface
	return args
		
def main():
	args = handleArguments()
	name = input("Choose the ssid of the network you will advertize: ")
	length = int(input("Choose the length of the ssid that will be shown to the device: "))

	print('\n' + 'Attacker Initialized')
	print('Attacking the target: ' + target + '\n')

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
