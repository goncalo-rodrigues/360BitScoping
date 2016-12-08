import dpkt
import socket
import sys, getopt
import numpy as np
from scapy.all import *
from tracker_filter import tracker_filter, print_output
from HandShakeTracker import HandhakeFilter
from PieceFilter import PieceFilter
from AttributeMeters import *
from PortFilter import PortFilter
from subprocess import call
import os

start_time = 0

np.set_printoptions(threshold=np.nan, precision=3)

def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def DPIComponent(filepath, out_pcap=None):
    global start_time
    start_time = time.time()
    print "%.3fs: starting read" % (time.time() - start_time)
    f = open(filepath)
    pcap = dpkt.pcap.Reader(f)

    torrent_streams = get_all_streams(pcap)

    def apply_function(stream_id,ts,buffer):
        if out_pcap is not None:
            out_pcap.writepkt(buffer, ts)

    iterate_over_streams(pcap, torrent_streams, apply_function)


    print "%.3fs: done filtering" % (time.time() - start_time)
    # print "downloaded: %s" % str(downstreams_lengths)
    # print "uploaded: %s" % str(upstreams_lengths)
    f.close()


#Assumes all dictionaries have the exacts same keys
def merge_features(*args):
    if len(args) == 0:
        return None

    result = dict((stream, []) for stream in args[0].keys())
    for key in result.keys():
        result[key] = [feature[key] for feature in args]
    return result



# apply_function : (StreamId s_id) x (int timestamp) x (byte[] buf) => void
def iterate_over_streams(pcap, streams, *apply_functions):
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data

        pkt = ip.data

        if pkt is None:
            continue

        protocol_str = "UNK"
        if isinstance(pkt, dpkt.tcp.TCP):
            protocol_str = "TCP"
        elif isinstance(pkt, dpkt.udp.UDP):
            protocol_str = "UDP"
        else:
            continue

        sport, dport = "unk_port", "unk_port"
        try:
            sport = pkt.sport
            dport = pkt.dport
        except AttributeError:
            pass



        stream_id = StreamId((ip.src, sport), (ip.dst, dport), protocol_str)
        # Already identified this stream
        if streams.has_key(stream_id):
            for fun in apply_functions:
                fun(stream_id, timestamp, buf)



def get_all_streams(pcap):
    result = {}
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        pkt = ip.data

        if pkt is None:
            continue

        protocol_str = "UNK"
        if isinstance(pkt, dpkt.tcp.TCP):
            protocol_str = "TCP"
        elif isinstance(pkt, dpkt.udp.UDP):
            protocol_str = "UDP"
        else:
            continue

        sport, dport = "unk_port", "unk_port"
        try:
            sport = pkt.sport
            dport = pkt.dport
        except AttributeError:
            pass

        stream_id = StreamId((ip.src, sport), (ip.dst, dport), protocol_str)
        # Already identified this stream
        if result.has_key(stream_id):
            continue

        success, output = is_torrent(pkt)
        if not success:
            continue

        result[stream_id] = output
        print "New Stream %s" % str(stream_id)
    return result

"""
def is_torrent(pkt):
    filters = [tracker_filter, HandhakeFilter, PieceFilter]
    for filt in filters:
        torrent, output = filt(pkt)
        if torrent:
            return torrent, output
    return False, {}

"""

def is_torrent(pkt):
    torrent, output = PortFilter(pkt)
    if not torrent:
        #print output['sport'],output['dport']
        return False, {}

    filters = [tracker_filter, HandhakeFilter, PieceFilter]

    for filt in filters:
        torrent, output = filt(pkt)
        if torrent:
            return torrent, output
    return False, {}

# Uniformalizes stream_ids so it outputs the same whether it is incoming or outgoing
# A_IP:sport -> B_IP:dport outputs the same StreamId as B_IP:dport -> A_IP:sport
def uniStreamToBiStream(stream_id):
    srcip, dstip, sport, dport = stream_id.getSrcIp(), stream_id.getDstIp(), stream_id.getSrcPort(), stream_id.getDstPort()
    if srcip < dstip:
        return stream_id
    else:
        return StreamId((dstip, dport), (srcip, sport), stream_id.getProtocol(), False)

class StreamId:

    def __init__(self, srctuple, dsttuple, protocol, raw_inet_addresses = True):
        if not raw_inet_addresses:
            self.entities = (srctuple, dsttuple)
        else:
            self.entities = ((inet_to_str(srctuple[0]), srctuple[1]),
                         (inet_to_str(dsttuple[0]), dsttuple[1]))
        self.protocol = protocol

    def __repr__(self):
        return '%s: %s:%s -> %s:%s' % \
                      (self.protocol,
                       self.entities[0][0],
                       self.entities[0][1],
                       self.entities[1][0],
                       self.entities[1][1])

    def __eq__(self, other):
        if not isinstance(other, StreamId):
            return False
        return self.entities == other.entities and \
        self.protocol == other.protocol



    def __hash__(self):
        return self.entities.__hash__() + self.protocol.__hash__()

    def getSrcIp(self):
        return self.entities[0][0]
    def getSrcPort(self):
        return self.entities[0][1]
    def getDstIp(self):
        return self.entities[1][0]
    def getDstPort(self):
        return self.entities[1][1]
    def getProtocol(self):
        return self.protocol
