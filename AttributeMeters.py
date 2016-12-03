import dpkt
import math
import numpy as np
import random
vector_size = 256
random.seed(5274)
hash_table_4_bits = [random.randint(0, 15) for i in range(256)]
def DirectionPacketLengthDistributionMeter(stream):
    max_tcp_size = 2**16
    # max tcp packet size is 2**16. this assures exponent**128 = 2**16, so we use all bits in the vector
    exponent = 2**(math.log(max_tcp_size, 2) / (float(vector_size) / 2))
    def GetPacketBinNumber(packet_length):
        if packet_length == 0:
            return 0
        return min(math.floor(math.log(packet_length, exponent)), vector_size/2 - 1)

    client = ""
    server = ""
    result_vector = np.zeros(vector_size, dtype=int)
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
    result_vector = np.zeros(vector_size, dtype=int)
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


def First4PacketsByteFrequencyMeter(stream):
    result_vector = np.zeros(vector_size,  dtype=int)
    packets_seen = 0
    bytes_to_see = 100
    for _, buf in stream:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        pkt = ip.data

        if not (isinstance(pkt, dpkt.tcp.TCP) or isinstance(pkt, dpkt.udp.UDP)):
            continue

        offset = packets_seen * vector_size / 4
        data = pkt.data
        for i in range(min(bytes_to_see, len(data))):
            index = int(offset + (ord(data[i]) % (vector_size / 4)))
            result_vector[index] += 1

        packets_seen += 1
        if packets_seen >= 4:
            break

    return result_vector


def First2PacketsFirst8ByteHashDirectionCountsMeter(stream):
    # must produce a hash value between 0 and vector_size >> 4
    def hash(byte):
        #return byte * 11 % (vector_size >> 4)
        return hash_table_4_bits[byte]
    client = ""
    server = ""
    seen_packets = 0
    countersInc = np.zeros(vector_size >> 4, dtype=int)
    countersOut = np.zeros(vector_size >> 4, dtype=int)
    num_bytes = 8
    result_vector = np.zeros(vector_size,  dtype=int)
    for _, buf in stream:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        pkt = ip.data

        if not (isinstance(pkt, dpkt.tcp.TCP) or isinstance(pkt, dpkt.udp.UDP)):
            continue

        if client == "":
            client = ip.src
            server = ip.dst



        data = pkt.data
        for i in range(min(num_bytes, len(data))):
            h = hash(ord(data[i]))
            if client == ip.src: #outgoing
                countersOut[h] += 1
            else: #incoming
                countersInc[h] += 1

        seen_packets += 1
        if seen_packets >= 2:
            break

    print countersOut
    for i in range(len(countersOut)):
        result_vector[i*num_bytes + countersOut[i]] += 1
        result_vector[vector_size / 2 + i*num_bytes + countersInc[i]] += 1

    return result_vector



def relative_entropy(observed_attr, known_attr):
    return np.sum(np.multiply(observed_attr, (np.log(observed_attr) - np.log(known_attr))))
