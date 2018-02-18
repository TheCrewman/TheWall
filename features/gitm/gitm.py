from subprocess import check_output
from time import sleep
from signal import signal, SIGTERM
from sys import exit
from os import system

class Gitm(object):
    def __init__(self):
        self._gw_ip = check_output("route -n | grep -v \"tun0\" | head -n 3 | tail -n 1 | sed \"s/         /\\t/g\" | cut -f 2 | sed \"s/     /\\t/g\" | cut -f 1", shell=True).strip("\n")
        self._gw_mac = check_output("arp -a %s | tr \" \" \"\\t\" | cut -f 4" % (self._gw_ip), shell=True).strip("\n")
        self._guardian_enabled = True

    def monitoredTermination(self, signal_number, interrupted_frame):
        #system("su daniele -c \"notify-send \\\"Guardian-in-the-middle status changed\\\" \\\"Stopped\\\"\"")
        system("shred -n 3 -z features/gitm/.gitm.lock && rm -f features/gitm/.gitm.lock")
        exit(0)

    def start(self):
        #system("su daniele -c \"notify-send \\\"Guardian-in-the-middle status changed\\\" \\\"Started\\\"\"")
        system("touch features/gitm/.gitm.lock")
        signal(SIGTERM, self.monitoredTermination)

        while self._guardian_enabled == True:
            current_gw_mac = check_output("arp -a %s | tr \" \" \"\\t\" | cut -f 4" % (self._gw_ip), shell=True).strip("\n")

            if current_gw_mac != self._gw_mac:
                #system("su daniele -c \"notify-send -u critical \\\"MITM attack has been blocked!\\\" \\\"Attacker MAC address: %s\\\"\"" % (current_gw_mac))
                self._guardian_enabled = False
                system("shred -n 3 -z features/gitm/.gitm.lock && rm -f features/gitm/.gitm.lock")

            sleep(5)
