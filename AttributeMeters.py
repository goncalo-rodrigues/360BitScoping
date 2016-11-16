import dpkt
import math
import numpy as np
vector_size = 256
# max tcp packet size is 2**16. this assures exponent**128 = 2**16, so we use all bits in the vector
exponent = 2**(16 / (float(vector_size) / 2))

def DirectionPacketLengthDistributionMeter(stream):
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

        if client == ip.src:
            offset = 0
        else:
            offset = vector_size / 2

        index = int(offset + GetPacketBinNumber(len(pkt.data)))
        result_vector[index] += 1

    return result_vector




def GetPacketBinNumber(packet_length):
    if packet_length == 0:
        return 0
    return math.floor(math.log(packet_length, exponent))
