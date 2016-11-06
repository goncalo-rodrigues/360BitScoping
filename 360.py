#! /usr/bin/env python
import dpkt
import socket
import sys, getopt
from DPIComponent import DPIComponent
from scapy.all import *



def main(argv):
    output_file_path = ""
    try:
        opts, args = getopt.getopt(argv, "ho:", ["help"])
    except getopt.GetoptError:
        print 'for help use -h option'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'Help\nUsage: 360.py <options> <inputfile>\n\
where possible options include:\n\
-h\t\tShow this dialog\n\
-o <file>\tSave all detected packets to file'

            sys.exit()
        if opt == '-o':
            output_file_path = arg
    if len(args) == 0:
        print 'Missing argument: input capture file'
        sys.exit()

    if output_file_path != "":
        output_f = open(output_file_path, 'w+')
        out_pcap = dpkt.pcap.Writer(output_f)
    else:
        out_pcap = None
        output_f = None

    DPIComponent(args[0], out_pcap)

    try:
        output_f.close()
    except:
        pass
if __name__ == "__main__":
    main(sys.argv[1:])
