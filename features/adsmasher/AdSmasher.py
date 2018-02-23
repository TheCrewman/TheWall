from os import system, _exit
from scapy.all import *
from netfilterqueue import NetfilterQueue
from signal import signal, SIGTERM
import sqlite3

class AdSmasher(object):
    def __init__(self):
        self._nfqueue = NetfilterQueue()

        whitelist = open("features/adsmasher/whitelist.conf", "rb")
        self._whitelist_content = whitelist.read()
        whitelist.close()

        blacklist = open("features/adsmasher/blacklist.conf", "rb")
        self._blacklist_content = blacklist.readlines()
        blacklist.close()

        self._tmp_list = []
        self._suspicious_terms = ["ad", "cdn", "analytic", "partner", "static", "reward", "metric"]

        self._db_connector = sqlite3.connect("/home/pi/TheWall/logs/db/adsmasher.db")

    def adBlocker(self, packet):
        scapy_packet = IP(packet.get_payload())

        if scapy_packet.haslayer(DNS):
            requested_host = scapy_packet[DNS][DNSQR].qname[:len(scapy_packet[DNS][DNSQR].qname) - 1]

            if requested_host + "\n" in self._blacklist_content and "#%s" % (requested_host + "\n") not in self._blacklist_content and requested_host not in self._whitelist_content:
                cursor = self._db_connector.execute("SELECT Counter FROM logs WHERE Blacklisted_URL = \"%s\"" % (requested_host))

                for row in cursor:
                    counter = row[0]

                    self._db_connector.execute("UPDATE logs SET Counter = %d WHERE Blacklisted_URL = \"%s\"" % (counter + 1, requested_host))
                    self._db_connector.commit()

                packet.drop()

            else:
                for i in range(0, len(self._suspicious_terms)):
                    if self._suspicious_terms[i] in requested_host.lower() and requested_host not in self._tmp_list:
                        self._tmp_list.append(requested_host)
                        suspicious_list = open("features/adsmasher/suspicious.conf", "ab")
                        suspicious_list.write("%s\n" % (requested_host))
                        suspicious_list.close()

                packet.accept()
        else:
            packet.accept()

    def monitoredTermination(self, signal_number, interrupted_frame):
        self._db_connector.close()
        self._nfqueue.unbind()
        _exit(0)

    def start(self):
        self._nfqueue.bind(8, self.adBlocker)
        signal(SIGTERM, self.monitoredTermination)

        self._nfqueue.run()

    def stop(self):
        self._db_connector.close()
        self._nfqueue.unbind()
        _exit(0)
