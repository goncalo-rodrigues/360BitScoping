import dpkt
import socket
import binascii

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % ord(b) for b in address)


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


f = open("/root/360BitScoping/pcaps/small_torrent.pcap")
pcap = dpkt.pcap.Reader(f)

# For each packet in the pcap process the contents
for timestamp, buf in pcap:

    # Print out the timestamp in UTC
    # print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    eth = dpkt.ethernet.Ethernet(buf)
    # print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

    # Make sure the Ethernet frame contains an IP packet
    if not isinstance(eth.data, dpkt.ip.IP):
        # print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
        continue

    # Now unpack the data within the Ethernet frame (the IP packet)
    # Pulling out src, dst, length, fragment info, TTL, and Protocol
    ip = eth.data

    # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
    do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
    more_fragments = bool(ip.off & dpkt.ip.IP_MF)
    fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
    pkt = ip.data
    if isinstance(pkt, dpkt.tcp.TCP):
        #print "TCP"
        payload = pkt.data
        trying = binascii.hexlify(payload)
        conversion = ""
        if "13426974546f7272656e742070726f746f636f6c" in trying :
            print 'IP: %s -> %s' % ((inet_to_str(ip.src), inet_to_str(ip.dst)))
            print trying
    '''elif isinstance(pkt, dpkt.udp.UDP):
        print "UDP"

    try:
        print pkt.sport
    except AttributeError:
        print "error"
    print 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
          (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)
'''
f.close()
