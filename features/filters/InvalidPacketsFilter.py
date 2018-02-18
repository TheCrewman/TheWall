from netfilterqueue import NetfilterQueue
from scapy.all import *
from signal import signal, SIGTERM
from sys import exit
from os import system

class InvalidPacketsFilter(object):
    def __init__(self):
        self._nfqueue = NetfilterQueue()

    def filterPackets(self, packet):
        #scapy_packet = IP(packet.get_payload())

        #print " -------- INIZIO PACCHETTO --------\n\n\n"
        #print scapy_packet.show()
        #print "\n\n\n -------- FINE PACCHETTO --------\n\n\n"

        packet.accept()

    def monitoredTermination(self, signal_number, interrupted_frame):
        self._nfqueue.unbind()
        #system("su daniele -c \"notify-send \\\"Invalid packets filter status changed\\\" \\\"Stopped\\\"\"")
        exit(0)

    def start(self):
        self._nfqueue.bind(2, self.filterPackets)
        #system("su daniele -c \"notify-send \\\"Invalid packets filter status changed\\\" \\\"Started\\\"\"")
        signal(SIGTERM, self.monitoredTermination)
        self._nfqueue.run()

    def stop(self):
        self._nfqueue.unbind()
        #system("su daniele -c \"notify-send \\\"Invalid packets filter status changed\\\" \\\"Stopped\\\"\"")
        exit(0)
