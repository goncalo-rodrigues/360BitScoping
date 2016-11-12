import dpkt
import socket
import binascii

#Well-known ports
MIN_PORT = 0
MAX_PORT = 1024

#-----------------------------------------------------------------------

def getPorts(packet):
    return packet.sport, packet.dport


def PortFilter(packet):
    sport, dport = getPorts(packet)
    if (sport >= MIN_PORT and dport >= MIN_PORT) and \
        (sport <= MAX_PORT and dport <= MAX_PORT):

        return False, {'sport':sport, 'dport':dport}
    return True, {'sport':sport, 'dport':dport}
