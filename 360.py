#! /usr/bin/env python
import dpkt
import socket
import sys, getopt
from DPIComponent import DPIComponent
from scapy.all import *
import os
import thread
from SPIDComponent import SPIDComponent

SIZE_THRESHOLD_MB = 3000
SIZE_SPLIT_MB = 500
negative_pcap_path = "not_torrent.pcap"
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

    in_pcap = args[0]
    size_mb = os.stat(in_pcap).st_size/1024.0/1024.0

#------------------------------------------------------------------------------
#For multithreading purposes

    if size_mb > SIZE_THRESHOLD_MB:
        out_pcap = None
        output_f = None
        os.system("tcpdump -r "+in_pcap+" -w "+in_pcap+"_seg -C "+ str(SIZE_SPLIT_MB))
        dir = os.path.dirname(in_pcap)
        for file in os.listdir(dir):
            ext = file[file.find(".pcap"):]
            if "_seg" in ext:
                seg = file[-1]
                if seg == 'g':
                    seg = 0
                path = dir+"/"+file
                output_f = open(output_file_path+"_seg"+str(seg), 'w+')

                out_pcap = dpkt.pcap.Writer(output_f)
                thread.start_new_thread(DPIComponent, (path, out_pcap))

#------------------------------------------------------------------------------

    else:
        if output_file_path != "":
            output_f = open(output_file_path, 'w+')
            out_pcap = dpkt.pcap.Writer(output_f)
        else:
            out_pcap = None
            output_f = None
        negative_f = open(negative_pcap_path, 'w+')
        negative_pcap = dpkt.pcap.Writer(negative_f)
        DPIComponent(in_pcap, negative_pcap, out_pcap)
        negative_f.close()
        SPIDComponent(negative_pcap_path, out_pcap)



    try:
        output_f.close()
    except:
        pass
if __name__ == "__main__":
    main(sys.argv[1:])


