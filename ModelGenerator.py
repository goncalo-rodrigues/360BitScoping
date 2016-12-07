#! /usr/bin/env python
import os
from subprocess import call
import argparse
import numpy as np
from AttributeMeters import *
model_dir = "model_streams"
splitter_name = "./PcapSplitter"

np.set_printoptions(threshold=np.nan, precision=4, suppress=True)
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_files", nargs="+", help="Capture files to train the model")
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
    return model / np.sum(model, axis=1)[:, None]


def generate_model(file_list):
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)
    print file_list
    for file_name in file_list:
        call([splitter_name, "-f", file_name,  "-o", model_dir, "-m", "connection"])

    model = None
    for stream_file in os.listdir(model_dir):
        f = open(os.path.join(model_dir, stream_file))
        result = generate_stream_model(f)
        if model is None:
            model = result
        else:
            model += result

    model = normalize_model(model)

    print model


    #model = np.concatenate(result)

if __name__ == "__main__":
    main()
