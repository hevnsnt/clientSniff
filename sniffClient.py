#!/usr/bin/env python
# The previous line ensures that this script is run under the context
# of the Python interpreter. Next, import the needed functions:
from scapy.all import *
from os import system

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[1;34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

# Define the interface name that we will be sniffing from, you can
# change this if needed.
interface = "mon0"

# Next, declare a Python dictionary that we will use to keep track of client MAC addresses
# and number of packets seen.  Ex. '00:00:00:00:00:00': 34
observedclients = {}
observedAPs = ()

# The sniffmgmt() function is called each time Scapy receives a packet
# (we'll tell Scapy to use this function below with the sniff() function).
# The packet that was sniffed is passed as the function argument, "p".
def sniffmgmt(p):
    # Define our tuple (an immutable list) of the 3 management frame
    # subtypes sent exclusively by clients. I got this list from Wireshark.
    stamgmtstypes = (0, 2, 4, 8, 20)

    # Make sure the packet has the Scapy Dot11 layer present
    if p.haslayer(Dot11):

        # Check to make sure this is a management frame (type=0) and that
        # the subtype is one of our management frame subtypes indicating a
        # a wireless client
        if p.type <= 3 and p.subtype in stamgmtstypes:

            # We only want to print the MAC address of the client if it
            # hasn't already been observed. Check our list and if the
            # client address isn't present, print the address and then add
            # it to our list.
            if p.addr2 not in observedclients:
                observedclients[p.addr2] = 1
            else:
                observedclients[p.addr2] += 1
            #print p.addr2
            #observedclients.append(p.addr2)
        else:
            dict = {'ssid':p.info, 'bssid':p.addr2}
            observedAPs.append(dict)
            #if p.addr2 not in observedAPs:
            #    observedAPs['BSSID'] = p.addr2
            #    observedAPs['SSID'] = p.info
    
    printDictionary(observedclients, observedAPs)

# With the sniffmgmt() function complete, we can invoke the Scapy sniff()
# function, pointing to the monitor mode interface, and telling Scapy to call
# the sniffmgmt() function for each packet received. Easy!

def printDictionary(clients, aps):
    os.system('clear')
    print '['+G+'*'+W+'] Client List'
    for key, value in clients.iteritems():
        print('%s - [%s]' % (key, value))
    print()
    print '['+G+'*'+W+'] AP List'
    for AP in observedAPs:
         print AP['ssid'] '['+G+':'+W+']' AP['bssid']

def sniffClients():
    sniff(iface=interface, prn=sniffmgmt)

def startmon():
    print('[*] No %s interface found' % interface)
    if raw_input('[?] Would you like me to try to enable monitor mode? [y/n]: ').upper() == 'Y' or 'YES':
        print('')
        print('#' * 15 + '-- Listing Interfaces --' + '#' * 15)
        printInt()
        print('#' * 15 + '-- Listing Interfaces --' + '#' * 15)
        print('')
        monInt = raw_input('What interface would you like to monitor?: ')
        print "[+] Attempting to start monitor mode:"
        system('airmon-ng start %s > /dev/null' % monInt)
        print('[+] Attempting to sniff clients')
        sniffClients()
    else:
        print('[-] Exiting')

def printInt():
    system('airmon-ng | grep phy')

try:
    sniffClients()
except socket.error:
    startmon()
except Exception, e:
    raise
