#! /usr/bin/env python
import dpkt
import socket
import sys, getopt
from DPIComponent import DPIComponent
import os
import thread
from SPIDComponent import SPIDComponent
from tabulate import tabulate

SIZE_THRESHOLD_MB = 3000
SIZE_SPLIT_MB = 500
negative_pcap_path = "not_torrent.pcap"
final_output = {'total_packets': 0, 'total_size': 0, 'info_by_ip': {}}
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
        DPIComponent(in_pcap, final_output, negative_pcap, out_pcap)
        negative_f.close()
        SPIDComponent(negative_pcap_path, final_output, out_pcap)
        # if total traffic is lower than threshold value, then dont bother showing it in table
        threshold = 5000
        table_guilty = [(ip, final_output['info_by_ip'][ip]['downloaded'], final_output['info_by_ip'][ip]['uploaded'])
                        for ip in final_output['info_by_ip'].keys()
                        if final_output['info_by_ip'][ip]['downloaded'] + final_output['info_by_ip'][ip]['uploaded'] > threshold]
        # sort by downloaded tarffic
        table_guilty.sort(key=lambda x: -x[1])
        table_guilty = [(x[0], sizeof_fmt(x[1]), sizeof_fmt(x[2])) for x in table_guilty]
        if len(table_guilty) > 0:
            print tabulate(table_guilty, ['IP Address', 'Downloaded traffic', 'Uploaded traffic']), '\n'
        print "Total packets identified as torrent: %d" % final_output['total_packets']
        print "Total torrent traffic size: %s" % sizeof_fmt(final_output['total_size'])


    try:
        output_f.close()
    except:
        pass


from math import log
unit_list = zip(['bytes', 'kB', 'MB', 'GB', 'TB', 'PB'], [0, 0, 1, 2, 2, 2])
def sizeof_fmt(num):
    """Human friendly file size"""
    if num > 1:
        exponent = min(int(log(num, 1024)), len(unit_list) - 1)
        quotient = float(num) / 1024**exponent
        unit, num_decimals = unit_list[exponent]
        format_string = '{:.%sf} {}' % (num_decimals)
        return format_string.format(quotient, unit)
    if num == 0:
        return '0 bytes'
    if num == 1:
        return '1 byte'

if __name__ == "__main__":
    main(sys.argv[1:])




