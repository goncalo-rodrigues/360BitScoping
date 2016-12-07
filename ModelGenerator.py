#! /usr/bin/env python
import os
from subprocess import call
import argparse
import numpy as np
import shutil
from AttributeMeters import *
model_dir = "model_streams"
splitter_name = "./PcapSplitter"
bpf_filter = "(not tcp port (80 or 8000 or 8080 or 443 or 2869)) and tcp or udp" #"not tcp port (80 or 8000 or 8080 or 443 or 2869)"
smoothing = 0.0000000001

np.set_printoptions(threshold=np.nan, precision=4, suppress=True)
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_files", nargs="+", help="Traffic capture (.pcap) files to train the model")
    args = parser.parse_args()
    generate_model(args.input_files)


def generate_stream_model(file):
    meters = [DirectionPacketLengthDistributionMeter, NibblePositionPopularityMeter, First4PacketsByteFrequencyMeter, \
              First2PacketsFirst8ByteHashDirectionCountsMeter, FirstBitPositionsMeter, First2OrderedFirstBitPositionsMeter, \
              AccumulatedDirectionBytesMeter, First4PacketsFirst32BytesEqualityMeter]

    result = np.zeros((len(meters), vector_size))
    for i in range(len(meters)):
        meter = meters[i]
        file.seek(0)
        stream = dpkt.pcap.Reader(file)
        result[i, :] = meter(stream)

    return result


def normalize_model(model):
    model.dtype = float
    sumdiv = np.sum(model, axis=1)[:, None]
    sumdiv[sumdiv==0] = 1
    return model / sumdiv


def generate_model(file_list):

    shutil.rmtree(model_dir, ignore_errors=True)
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)

    print file_list
    for file_name in file_list:
        call([splitter_name, "-i", bpf_filter, "-f", file_name,  "-o", model_dir, "-m", "connection"])

    model = None
    for stream_file in os.listdir(model_dir):
        f = open(os.path.join(model_dir, stream_file))
        result = generate_stream_model(f)
        if model is None:
            model = result
        else:
            model += result
        f.close()

    model = normalize_model(model)

    print model[0]
    is_torrent_stream(open(os.path.join(model_dir, "wallpapers-0085.pcap")), model)
    return model

def relative_entropy(observed_attr, known_attr):
    return np.sum(np.multiply(observed_attr, (np.log(observed_attr+smoothing) - np.log(known_attr+smoothing))))

def is_torrent_stream(stream_file, torrent_model):
    # stream_fingerprints = normalize_model(generate_stream_model(stream_file)).reshape((-1,))
    # # concatenate array values
    # torrent_model = torrent_model.reshape((-1,))
    # entropy = relative_entropy(stream_fingerprints, torrent_model)
    #print entropy
    stream_fingerprints = normalize_model(generate_stream_model(stream_file))
    print stream_fingerprints[0]
    for i in range(stream_fingerprints.shape[0]):
        print relative_entropy(stream_fingerprints[i], torrent_model[i])

#-------------------------------------------------------
#PRE-PROCESSING
#-------
def pre_process(folder):
    pass
    
if __name__ == "__main__":
    main()
