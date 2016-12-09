import dpkt
import socket
import sys, getopt
import numpy as np
from tracker_filter import tracker_filter, print_output
from HandShakeTracker import HandhakeFilter
from AttributeMeters import *
from PortFilter import PortFilter
from subprocess import call
import os

start_time = 0
total_size = 0
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


def DPIComponent(filepath, final_output, negative_pcap=None, out_pcap=None):
    global start_time, total_size
    start_time = time.time()
    total_size = os.stat(filepath).st_size
    f = open(filepath)
    pcap = dpkt.pcap.Reader(f)

    print "Executing DPI component"
    torrent_streams = get_all_streams(pcap)
    update_progress(0.5)

    def apply_function(stream_id,ts,buffer, torrent):
        if torrent:
            size = len(dpkt.ethernet.Ethernet(buffer).data.data)
            final_output['total_packets'] += 1
            final_output['total_size'] += size
            if final_output['info_by_ip'].has_key(stream_id.getSrcIp()):
                final_output['info_by_ip'][stream_id.getSrcIp()]['uploaded'] += size
            else:
                final_output['info_by_ip'][stream_id.getSrcIp()] = {}
                final_output['info_by_ip'][stream_id.getSrcIp()]['uploaded'] = size
                final_output['info_by_ip'][stream_id.getSrcIp()]['downloaded'] = 0
            if final_output['info_by_ip'].has_key(stream_id.getDstIp()):
                final_output['info_by_ip'][stream_id.getDstIp()]['downloaded'] += size
            else:
                final_output['info_by_ip'][stream_id.getDstIp()] = {}
                final_output['info_by_ip'][stream_id.getDstIp()]['downloaded'] = size
                final_output['info_by_ip'][stream_id.getDstIp()]['uploaded'] = 0
        if out_pcap is not None and torrent:
            out_pcap.writepkt(buffer, ts)
        elif negative_pcap is not None and not torrent:
            negative_pcap.writepkt(buffer, ts)

    f.seek(0)
    pcap = dpkt.pcap.Reader(f)
    iterate_over_streams(pcap, torrent_streams, apply_function)
    update_progress(1)
    print '\n'

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
    size_read = 0
    for timestamp, buf in pcap:
        size_read += len(buf)
        update_progress(0.5 + float(size_read) / (2*total_size))
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
        cant_be_trashed, _ = PortFilter(pkt)
        if cant_be_trashed:
            for fun in apply_functions:
                fun(stream_id, timestamp, buf, streams.has_key(stream_id))



def get_all_streams(pcap):
    result = {}
    size_read = 0
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        size_read += len(buf)
        update_progress(float(size_read) / (2*total_size))
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
        #print "New Stream %s" % str(stream_id)
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

    filters = [tracker_filter, HandhakeFilter]
    for filt in filters:
        torrent, output = filt(pkt)
        if torrent:
            #print "Detected by %s" % filt.__name__
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

import time, sys

# update_progress() : Displays or updates a console progress bar
## Accepts a float between 0 and 1. Any int will be converted to a float.
## A value under 0 represents a 'halt'.
## A value at 1 or bigger represents 100%
def update_progress(progress):
    barLength = 10 # Modify this to change the length of the progress bar
    status = ""
    if isinstance(progress, int):
        progress = float(progress)
    if not isinstance(progress, float):
        progress = 0
        status = "error: progress var must be float\r\n"
    if progress < 0:
        progress = 0
        status = "Halt...\r\n"
    if progress >= 1:
        progress = 1
        status = "Done...\r\n"
    block = int(round(barLength*progress))
    text = "\rPercent: [{0}] {1}% {2}".format( "#"*block + "-"*(barLength-block), progress*100, status)
    sys.stdout.write(text)
    sys.stdout.flush()
