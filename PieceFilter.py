import dpkt
import socket
import binascii

def isPiece(msg_type):
    return msg_type == '07'

def decimal(hex):
    return int(hex,16)

#-----------------------------------------------------------------------
# 1 byte = 2 hex chars

def PieceFilter(packet):
    if isinstance(packet, dpkt.tcp.TCP):
        payload = str(packet.data)
        hex_payload = binascii.hexlify(payload)
        message_type = hex_payload[8:10]

        if isPiece(message_type):
            """
            message_length = hex_payload[0:8]
            piece_index = hex_payload[10:18]
            piece_offset = hex_payload[18:26]
            """
            piece_data = hex_payload[26:]


            return True, {'piece': len(piece_data)/2}


    return False, {}
