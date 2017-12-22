## 360BitScoping

## 1 Description of functionality

The tool is tracks down the sources of incoming BitTorrent traffic within a local network, since this content can be illegal.
To achieve this goal, it collects all packets within the local network.
To identify what packets are related to BitTorrent traffic the tool filters through all the collected packets.
It will also output relevant information about the captured traffic such as: 
* The downloader’s IP address.
* The name of the torrent being downloaded, if possible.
* Size of total downloaded data.
* The date and time of the oldest and newest BitTorrent Packets received.
* A complete capture output file, if requested.

## 2 Usage instructions

./360.py <input pcap> [-o <output pcap>]

Example:

./360.py pcaps/small_torrent.pcap -o output

This tools is basded on [1]. For more detail, see the [report](g24-a-360bitscoping-report.pdf)

[1] Hjelmvik, E and John, W. Breaking and Improving Protocol Obfuscation. Department of Computer
Science and Engineering, Chalmers University of Technology, Technical Report No. 2010-05, ISSN 1652-
926X, 2010.
