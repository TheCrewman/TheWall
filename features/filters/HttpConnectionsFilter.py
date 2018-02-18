from netfilterqueue import NetfilterQueue
from scapy.all import *
from socket import gethostbyaddr, herror
from os import system, _exit
from signal import signal, SIGTERM
import datetime

class HttpConnectionsFilter(object):
    def __init__(self):
        self._nfqueue = NetfilterQueue()
        self._already_flagged = []

    def filterPackets(self, packet):
        scapy_packet = IP(packet.get_payload())

        if scapy_packet.haslayer(TCP):
            if scapy_packet[TCP].dport == 80 and scapy_packet[IP].dst not in self._already_flagged:
                now = datetime.datetime.now()
                log_file = open("/home/pi/TheWall/logs/http_connections.log", "ab")

                try:
                    log_file.write("[%s] %s (%s) --> %s (%s)\n" % (now.strftime("%d/%m/%Y %H:%M"), scapy_packet[IP].src, gethostbyaddr(scapy_packet[IP].src)[0], scapy_packet[IP].dst, gethostbyaddr(scapy_packet[IP].dst)[0]))
                except herror:
                    log_file.write("[%s] %s --> %s\n" % (now.strftime("%d/%m/%Y %H:%M"), scapy_packet[IP].src, scapy_packet[IP].dst))
                except:
                    pass

                self._already_flagged.append(scapy_packet[IP].dst)
                log_file.close()

        packet.accept()

    def monitoredTermination(self, signal_number, interrupted_frame):
        self._nfqueue.unbind()
        _exit(0)

    def start(self):
        self._nfqueue.bind(1, self.filterPackets)
        signal(SIGTERM, self.monitoredTermination)

        self._nfqueue.run()

    def stop(self):
        self._nfqueue.unbind()
        _exit(0)
