from netfilterqueue import NetfilterQueue
from scapy.all import *
from socket import gethostbyaddr, herror
from os import system, _exit
from signal import signal, SIGTERM
import datetime
import sqlite3

class HttpConnectionsFilter(object):
    def __init__(self):
        self._nfqueue = NetfilterQueue()
        self._already_flagged = []
        self._db_connector = sqlite3.connect("/home/pi/TheWall/logs/db/http_connections.db");

    def filterPackets(self, packet):
        scapy_packet = IP(packet.get_payload())

        if scapy_packet.haslayer(TCP):
            if scapy_packet[TCP].dport == 80 and scapy_packet[IP].dst not in self._already_flagged:
                now = datetime.datetime.now()
                date = now.strftime("%d/%m/%Y")
                time = now.strftime("%H:%M")

                try:
                    self._db_connector.execute("INSERT INTO logs (Date, Time, Source_IP, Source_hostname, Destination_IP, Destination_hostname) VALUES (\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\")" % (date, time, scapy_packet[IP].src, gethostbyaddr(scapy_packet[IP].src)[0], scapy_packet[IP].dst, gethostbyaddr(scapy_packet[IP].dst)[0]))
                    self._db_connector.commit()
                except herror:
                    self._db_connector.execute("INSERT INTO logs (Date, Time, Source_IP, Destination_IP) VALUES (\"%s\", \"%s\", \"%s\", \"%s\")" % (date, time, scapy_packet[IP].src, scapy_packet[IP].dst))
                    self._db_connector.commit()
                except:
                    pass

                self._already_flagged.append(scapy_packet[IP].dst)

        packet.accept()

    def monitoredTermination(self, signal_number, interrupted_frame):
        self._db_connector.close()
        self._nfqueue.unbind()
        _exit(0)

    def start(self):
        self._nfqueue.bind(1, self.filterPackets)
        signal(SIGTERM, self.monitoredTermination)

        self._nfqueue.run()

    def stop(self):
        self._db_connector.close()
        self._nfqueue.unbind()
        _exit(0)
