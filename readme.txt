--------------------------------------------
Members - GROUP 24

78264 - Pedro Afonso Guerreiro
78328 -	Pedro Miguel dos Santos Duarte
78958 - Gonçalo Alfredo dos Santos Rodrigues
--------------------------------------------

--------
Required
--------

Python v.2.7.6

-----------------------
Installing dependencies
-----------------------

pip install numpy
apt-get install python-dpkt
pip install tabulate


---------------------------
Model training instructions
---------------------------

./ModelGenerator.py <input pcap>

Example:

./ModelGenerator.py pcaps/im_100%_sure_this_only_has_torrent_packets.pcap

NOTE: This is not required as the model is already trained. Use only if you
want to train your own model.


------------------
Usage instructions
------------------

To see the help menu:
./360.py -h 


To use:
./360.py [-o <output pcap>] <input pcap> 

Example:

./360.py -o output pcaps/small_torrent.pcap 
