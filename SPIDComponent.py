from ModelGenerator import split_pcap_into_streams, is_torrent_stream, model_pathname
import dpkt
import os
import numpy as np
import shutil
from DPIComponent import inet_to_str, update_progress

temp_dir = "tmp"
def SPIDComponent(filepath, final_output, out_pcap=None):
    print 'Splitting pcap into stream files...'
    shutil.rmtree(temp_dir, ignore_errors=True)
    split_pcap_into_streams(filepath, temp_dir)
    negative_f = open("negative2.pcap", 'w+')
    negative_pcap = dpkt.pcap.Writer(negative_f)
    try:
        torrent_model = np.load(model_pathname + ".npy")
    except:
        print("Unable to read model. Have you run ModelGenerator yet?")
        return
    list_files = os.listdir(temp_dir)
    total_files = len(list_files)
    files_processed = 0.
    print 'Executing SPID component'
    for stream_file in list_files:
        update_progress(files_processed / total_files)
        f = open(os.path.join(temp_dir, stream_file))
        result = is_torrent_stream(f, torrent_model)
        if result:
            #print("Found torrent! %s" % stream_file)
            save_to_file(f, out_pcap, final_output)

        else:
            save_to_file(f, negative_pcap)
            #print("Non-torrent traffic! %s" % stream_file)
            f.close()
        files_processed += 1
    update_progress(1)
    print '\n'


def save_to_file(input_f, output, final_output=None):
    input_f.seek(0)
    stream = dpkt.pcap.Reader(input_f)
    for ts, buf in stream:
        if output is not None:
            output.writepkt(buf, ts)
        if final_output is not None:
            try:
                size = len(dpkt.ethernet.Ethernet(buf).data.data.data)
            except:
                return
            ipsrc = inet_to_str(dpkt.ethernet.Ethernet(buf).data.src)
            ipdst = inet_to_str(dpkt.ethernet.Ethernet(buf).data.dst)
            final_output['total_packets'] += 1
            final_output['total_size'] += len(dpkt.ethernet.Ethernet(buf).data.data)
            if final_output['info_by_ip'].has_key(ipsrc):
                final_output['info_by_ip'][ipsrc]['uploaded'] += size
            else:
                final_output['info_by_ip'][ipsrc] = {}
                final_output['info_by_ip'][ipsrc]['uploaded'] = size
                final_output['info_by_ip'][ipsrc]['downloaded'] = 0
            if final_output['info_by_ip'].has_key(ipdst):
                final_output['info_by_ip'][ipdst]['downloaded'] += size
            else:
                final_output['info_by_ip'][ipdst] = {}
                final_output['info_by_ip'][ipdst]['downloaded'] = size
                final_output['info_by_ip'][ipdst]['uploaded'] = 0
