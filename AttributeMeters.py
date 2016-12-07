import dpkt
import binascii
import math
import numpy as np
import random
vector_size = 256
random.seed(5274)
hash_table_4_bits = [random.randint(0, 15) for i in range(256)]
max_tcp_size = 2**16
# max tcp packet size is 2**16. this assures exponent**128 = 2**16, so we use all bits in the vector
exponent = 2**(math.log(max_tcp_size, 2) / (float(vector_size) / 2))
for i in range(2, vector_size / 2):
    linear_up_to = i
    if exponent ** i >= i:
        break




def DirectionPacketLengthDistributionMeter(stream):
    def GetPacketBinNumber(packet_length):

        if packet_length < linear_up_to:
            return packet_length
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

        if len(pkt.data) == 0:
            continue


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

    for i in range(len(countersOut)):
        result_vector[i*num_bytes + countersOut[i]] += 1
        result_vector[vector_size / 2 + i*num_bytes + countersInc[i]] += 1

    return result_vector

##############################################################################


def FirstBitPositionsMeter(stream):
    zero_value = 0
    one_value = 128
    packets_to_inspect = 8
    packets_inspected = 0
    result_vector = np.zeros(vector_size, dtype=int)

    for _, buf in stream:
        if packets_inspected >= packets_to_inspect:
            return result_vector
        else:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            pkt = ip.data

            if not (isinstance(pkt, dpkt.tcp.TCP) or isinstance(pkt, dpkt.udp.UDP)):
                continue
            data = pkt.data
            data_str = binascii.hexlify(data)

            if data_str == "":
                continue

            bit_array = bin(int(data_str, 16))
            bit_array = bit_array[2:]

            size = min(len(bit_array), 16 * 8)

            for index in range(size):
                value = bit_array[index]
                if value == "0":
                    result_vector[zero_value + index] += 1
                else:
                    result_vector[one_value + index] += 1
            packets_inspected += 1
    return result_vector


def First2OrderedFirstBitPositionsMeter(stream):
    zero_value = 0
    one_value = 128
    packet_jump = 64
    packets_to_inspect = 2
    bytes_to_inspect = 8
    packets_inspected = 0
    bytes_inspected = 0
    result_vector = np.zeros(vector_size,dtype = int)


    for _, buf in stream:
        if packets_inspected >= packets_to_inspect:
            return result_vector
        else:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            pkt = ip.data

            if not (isinstance(pkt, dpkt.tcp.TCP) or isinstance(pkt, dpkt.udp.UDP)):
                continue
            data = pkt.data
            data_str = binascii.hexlify(data)

            if data_str == "":
                continue

            bit_array = bin(int(data_str, 16))
            bit_array = bit_array[2:]

            size = min(len(bit_array), 8 * 8)

            for index in range (size):
                value = bit_array[index]
                if value == "0":
                    result_vector[zero_value + (packets_inspected * packet_jump) + index] += 1
                else:
                    result_vector[one_value + (packets_inspected * packet_jump) + index] += 1
            packets_inspected += 1
    return result_vector

def AccumulatedDirectionBytesMeter(stream):
    max_tcp_size = 2**16
    # max tcp packet size is 2**16. this assures exponent**128 = 2**16, so we use all bits in the vector
    current_client = ""
    previous_client =  ""
    dir_changes = 0
    byte_count = 0
    direction = True


    client = ""
    server = ""
    result_vector = np.zeros(vector_size, dtype=int)
    for _, buf in stream:

        if(dir_changes >= 4):
            return result_vector

        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        pkt = ip.data
        if not (isinstance(pkt, dpkt.tcp.TCP) or isinstance(pkt, dpkt.udp.UDP)):
            continue

        data_size = len(pkt.data)

        if current_client == "":
            current_client = ip.src
            previous_client = current_client
            direction = True

        current_client = ip.src

        byte_count += data_size
        direction_offset = dir_changes * vector_size / 4
        byte_count_offset = min((byte_count // 32), (vector_size // 4) - 1)
        result_vector[direction_offset + byte_count_offset] += 1

        if current_client != previous_client:
            direction = not direction
            byte_count = 0
            dir_changes += 1

        previous_client = current_client

    return result_vector


def First4PacketsFirst32BytesEqualityMeter(stream):
    def knuths_method(i):
        return i * 2654435761 % 256

    current_data = None
    previous_data = None
    packets_inspected = 0
    ignore = True
    result_vector = np.zeros(vector_size, dtype=int)

    for _, buf in stream:

        if(packets_inspected >= 4):
            return result_vector

        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        pkt = ip.data
        if not (isinstance(pkt, dpkt.tcp.TCP) or isinstance(pkt, dpkt.udp.UDP)):
            continue

        data = pkt.data
        current_data = data[:min(32, len(data))]

        if not ignore:
            equality_int = 0

            for i in range(min(len(current_data), len(previous_data))):
                equality_int <<= 1
                if previous_data[i] == current_data[i]:
                    equality_int += 1
            result_vector[knuths_method(equality_int)] += 1

        previous_data = current_data
        ignore = False
        packets_inspected += 1
    return result_vector

##############################################################################


