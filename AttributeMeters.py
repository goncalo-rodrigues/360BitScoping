import dpkt
import math
import numpy as np
vector_size = 256
max_tcp_size = 2**16
# max tcp packet size is 2**16. this assures exponent**128 = 2**16, so we use all bits in the vector
exponent = 2**(math.log(max_tcp_size, 2) / (float(vector_size) / 2))
np.set_printoptions(suppress=True)

def DirectionPacketLengthDistributionMeter(stream):
    def GetPacketBinNumber(packet_length):
        if packet_length == 0:
            return 0
        return math.floor(math.log(packet_length, exponent))

    client = ""
    server = ""
    result_vector = np.zeros(vector_size)
    for _, buf in stream:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        pkt = ip.data

        if not (isinstance(pkt, dpkt.tcp.TCP) or isinstance(pkt, dpkt.udp.UDP)):
            continue

        if client == "":
            client = ip.src
            server = ip.dst

        if not client == ip.src:
            offset = 0
        else:
            offset = vector_size / 2

        index = int(offset + GetPacketBinNumber(len(pkt.data)))
        result_vector[index] += 1

    return result_vector

def NibblePositionPopularityMeter(stream):
    client = ""
    server = ""
    packets_to_inspect = 8
    bytes_to_inspect = 16
    packets_inspected = 0
    result_vector = np.zeros(vector_size)
    nibble_counters = np.zeros((16, bytes_to_inspect*2))

    for _, buf in stream:
        if packets_inspected >= packets_to_inspect:
            return result_vector
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        pkt = ip.data

        if not (isinstance(pkt, dpkt.tcp.TCP) or isinstance(pkt, dpkt.udp.UDP)):
            continue

        if client == "":
            client = ip.src
            server = ip.dst

        if len(pkt.data) == 0:
            continue

        data = pkt.data
        sz = min(bytes_to_inspect, len(data))
        indices_temp = [(ord(byte) & 0x0F, ord(byte) >> 4 & 0x0F) for byte in data[:sz]]
        indices = [x for tup in indices_temp for x in tup]

        for idx, nibble in enumerate(indices):
            popRank = 0
            for i in range(16):
                if nibble_counters[i, idx] > nibble_counters[nibble, idx]:
                    popRank += 1

            nibble_counters[nibble, idx] += 1
            result_vector[packets_to_inspect*idx + popRank] += 1

        packets_inspected += 1
    return result_vector


