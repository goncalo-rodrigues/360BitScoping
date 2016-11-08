import dpkt
import socket
import sys, getopt
from scapy.all import *
from tracker_filter import tracker_filter, print_output
from HandShakeTracker import HandhakeFilter
start_time = 0

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
    torrent_streams = {}
    start_time = time.time()
    print "%.3fs: starting read" % (time.time() - start_time)
    f = open(filepath)
    pcap = dpkt.pcap.Reader(f)

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
        if stream_id in torrent_streams.keys():
            continue

        success, output = is_torrent(pkt)
        if not success:
            continue

        torrent_streams[stream_id] = output
        print "Identified: %s" % str(stream_id)
    print "%.3fs: done filtering" % (time.time() - start_time)


def is_torrent(pkt):
    filters = [tracker_filter, HandhakeFilter]
    for filt in filters:
        torrent, output = filt(pkt)
        if torrent:
            return torrent, output
    return False, {}


class StreamId:

    def __init__(self, srctuple, dsttuple, protocol):
        self.entities = (srctuple, dsttuple)
        self.protocol = protocol

    def __repr__(self):
        return '%s: %s:%s -> %s:%s' % \
                      (self.protocol,
                       inet_to_str(self.entities[0][0]),
                       self.entities[0][1],
                       inet_to_str(self.entities[1][0]),
                       self.entities[1][1])

    def __eq__(self, other):
        if not isinstance(other, StreamId):
            return False
        self.entities == other.entities and \
        self.protocol == other.protocol



    def __hash__(self):
        return self.entities.__hash__() + self.protocol.__hash__()
