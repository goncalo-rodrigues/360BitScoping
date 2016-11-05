import dpkt
import socket
import binascii

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def isBitTorrentHandshake(hexlified_tcp_payload):
    if "13426974546f7272656e742070726f746f636f6c" in hexlified_tcp_payload:
        return True
    else:
        return False
def decodeRegularClient(client_str):
    mapping = {'AG' : 'Ares',
        "A~" : 'Ares',
        'AR' : 'Arctic',
        'AV' : 'Avicora',
        'AX' : 'BitPump',
        'AZ' : 'Azureus',
        'BB' : 'BitBuddy',
        'BC' : 'BitComet',
        'BF' : 'Bitflu',
        'BG' : 'BTG',
        'BR' : 'BitRocket',
        'BS' : 'BTSlave',
        'BT' : 'BitTorrent',
        'BX' : 'Bittorrent X',
        'CD' : 'Enhanced CTorrent',
        'CT' : 'CTorrent',
        'DE' : 'DelugeTorrent',
        'DP' : 'Propagate Data Client',
        'EB' : 'EBit',
        'ES' : 'Electric Sheep',
        'FT' : 'FoxTorrent',
        'FX' : 'Freebox BitTorrent',
        'GS' : 'GSTorrent',
        'HL' : 'Halite',
        'HN' : 'Hydranode',
        'KG' : 'KGet',
        'KT' : 'KTorrent',
        'LH' : 'LH:ABC',
        'LP' : 'Lphant',
        'LT' : 'LibTorrent',
        'lt' : 'LibTorrent',
        'LW' : 'LimeWire',
        'MO' : 'MonoTorrent',
        'MP' : 'MooPolice',
        'MR' : 'Miro',
        'MT' : 'MoonlightTorrent',
        'NX' : 'Net Transport',
        'PD' : 'Pando',
        'qB' : 'qBittorrent',
        'QD' : 'QQDownload',
        'QT' : ',Qt 4 Torrent',
        'RT' : 'Retriever',
        'S~' : 'Shareaza',
        'SB' : 'Swiftbit',
        'SS' : 'SwarmScope',
        'ST' : 'SymTorrent',
        'st' : 'SharkTorrent',
        'SZ' : 'Shareaza',
        'TN' : 'TorrentDotNET',
        'TR' : 'Transmission',
        'TS' : 'Torrentstorm',
        'TT' : 'TuoTu',
        'UL' : 'uLeecher',
        'UT' : 'uTorrent',
        'VG' : 'Vagaa',
        'WD' : 'WebTorrent Desktop',
        'WT' : 'BitLet',
        'WW' : 'WebTorrent',
        'WY' : 'FireTorrent',
        'XL' : 'Xunlei',
        'XT' : 'XanTorrent',
        'XX' : 'Xtorrent',
        'ZT' : 'ZipTorrent' }

    translated="Unknown Standard Client"
    mappedID = ""
    clientID = client_str[0:2]
    clientVersion = client_str[2:]
    mappedID = mapping[clientID]
    if mappedID != "":
        translated = mapping[clientID] + " " + clientVersion[0] + "." + clientVersion[1] + "." + clientVersion[2]
    return translated


def translateTorrentClient(client):
    if client[0] == "-" and client[7] == "-":
        client = client[1:7]
        readable_client = decodeRegularClient(client)
    else:
        return "Custom Shad0w BitTorrent Client Implementation"



f = open("/root/360BitScoping/pcaps/small_torrent.pcap")
pcap = dpkt.pcap.Reader(f)

for timestamp, buf in pcap:

    eth = dpkt.ethernet.Ethernet(buf)

    if not isinstance(eth.data, dpkt.ip.IP):
        continue
    ip = eth.data

    # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
    do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
    more_fragments = bool(ip.off & dpkt.ip.IP_MF)
    fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
    pkt = ip.data
    if isinstance(pkt, dpkt.tcp.TCP):
        payload = pkt.data
        #Hexlify the payload for easier info carving
        hexlified_payload = binascii.hexlify(payload)
        if isBitTorrentHandshake(hexlified_payload):
            #Scrap out the bytes that identify the Protocol (20 bytes so 40 hexcharaters in the hexstring)
            hexlified_payload = hexlified_payload[40:]
            #BitTorrent Detected Gather Source IP and Destination IP
            source_ip = inet_to_str(ip.src)
            dest_ip = inet_to_str(ip.dst)
            #remove extension Bytes (8bytes so 16 hexcharactes in the hexstring)
            hexlified_payload = hexlified_payload[16:]
            signature = hexlified_payload[0:40]
            #remove the read signature
            hexlified_payload = hexlified_payload[40:]
            #read the client in ascii (1st 8bytes 16hexcharacters from the peerid field)
            torrentclient = str(binascii.unhexlify(hexlified_payload[0:16]))

            print 'Source IP: %s\nDestinationIP: %s\nSignature: %s\nTorrentClient: %s\n' % \
                (inet_to_str(ip.src), inet_to_str(ip.dst), signature, translateTorrentClient(torrentclient))
f.close()
