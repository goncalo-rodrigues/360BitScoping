import dpkt
import socket
import binascii

#RANGE
MIN_PORT = 0
MAX_PORT = 1024

#
OTHER_KNOWN_PORTS = []

#-----------------------------------------------------------------------

def getPorts(packet):
    return packet.sport, packet.dport

def isKnown(port):
    return port >= MIN_PORT and port <= MAX_PORT \
            and port not in OTHER_KNOWN_PORTS


def PortFilter(packet):
    sport, dport = getPorts(packet)
    if isKnown(sport) or isKnown(dport):
        return False, {'sport':sport, 'dport':dport}

    return True, {'sport':sport, 'dport':dport}
