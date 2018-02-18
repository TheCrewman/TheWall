from netfilterqueue import NetfilterQueue
from scapy.all import *
from os import system
from signal import signal, SIGTERM
from sys import exit

class GeneralPurposeFilter(object):
    def __init__(self):
        self._nfqueue = NetfilterQueue()
        self._log_file = open("logs/filtered_packets.log", "ab")
        self._already_flagged = ""

    def filterPackets(self, packet):
        scapy_packet = IP(packet.get_payload())

        log_text = " -------- INIZIO PACCHETTO --------\n\n\n\n%s\n\n\n\n -------- FINE PACCHETTO --------\n\n\n" % (scapy_packet.summary())
        self._log_file.write(log_text)

        # Detect ICMP echo-requests towards local host
        if scapy_packet.haslayer(ICMP):
            if scapy_packet[ICMP].type == 8 and scapy_packet[IP].src != self._already_flagged:    # 8 --> echo-request
                #system("su daniele -c \"notify-send \\\"ICMP echo-request found\\\" \\\"%s is pinging you!\\\"\"" % (scapy_packet[IP].src))
                self._already_flagged = scapy_packet[IP].src

        packet.accept()

    def monitoredTermination(self, signal_number, interrupted_frame):
        self._nfqueue.unbind()
        self._log_file.close()
        #system("su daniele -c \"notify-send \\\"General purpose filter status changed\\\" \\\"Stopped\\\"\"")
        exit(0)

    def start(self):
        self._nfqueue.bind(3, self.filterPackets)
        #system("su daniele -c \"notify-send \\\"General purpose filter status changed\\\" \\\"Started\\\"\"")
        signal(SIGTERM, self.monitoredTermination)
        self._nfqueue.run()

    def stop(self):
        self._nfqueue.unbind()
        self._log_file.close()
        #system("su daniele -c \"notify-send \\\"General purpose filter status changed\\\" \\\"Stopped\\\"\"")
        exit(0)
