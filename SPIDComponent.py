from ModelGenerator import split_pcap_into_streams, is_torrent_stream, model_pathname
import dpkt
import os
import numpy as np

temp_dir = "tmp"
def SPIDComponent(filepath, out_pcap=None):

    split_pcap_into_streams(filepath, temp_dir)

    try:
        torrent_model = np.load(model_pathname + ".npy")
    except:
        print("Unable to read model. Have you run ModelGenerator yet?")
        return

    for stream_file in os.listdir(temp_dir):
        f = open(os.path.join(temp_dir, stream_file))
        result = is_torrent_stream(f, torrent_model)
        if result:
            print("Found torrent!")
            if out_pcap is not None:
                save_to_file(f, out_pcap)
        f.close()


def save_to_file(input_f, output):
    input_f.seek(0)
    stream = dpkt.pcap.Reader(input_f)
    for ts, buf in stream:
        output.writepkt(buf, ts)
