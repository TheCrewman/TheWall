#!/usr/bin/python2

import sys
from os import system
from multiprocessing import Process
from subprocess import check_output

sys.path.append("features/filters")
from HttpConnectionsFilter import HttpConnectionsFilter
from InvalidPacketsFilter import InvalidPacketsFilter
from GeneralPurposeFilter import GeneralPurposeFilter

sys.path.append("features/gitm")
from gitm import Gitm

sys.path.append("features/adsmasher")
from AdSmasher import AdSmasher

def splashcreen():
    system("clear")

    # ASCII art made by http://www.patorjk.com (http://www.patorjk.com/software/taag/#p=display&f=Big%20Money-ne&t=TheWall)
    print
    print " /$$$$$$$$ /$$                 /$$      /$$           /$$ /$$"
    print "|__  $$__/| $$                | $$  /$ | $$          | $$| $$"
    print "   | $$   | $$$$$$$   /$$$$$$ | $$ /$$$| $$  /$$$$$$ | $$| $$"
    print "   | $$   | $$__  $$ /$$__  $$| $$/$$ $$ $$ |____  $$| $$| $$"
    print "   | $$   | $$  \ $$| $$$$$$$$| $$$$_  $$$$  /$$$$$$$| $$| $$"
    print "   | $$   | $$  | $$| $$_____/| $$$/ \  $$$ /$$__  $$| $$| $$"
    print "   | $$   | $$  | $$|  $$$$$$$| $$/   \  $$|  $$$$$$$| $$| $$"
    print "   |__/   |__/  |__/ \_______/|__/     \__/ \_______/|__/|__/"
    print

def checkIptablesRules(rules):
    iptables_conf_file = open("conf/wall_iptables.conf", "rb")
    iptables_rules = iptables_conf_file.read()
    iptables_conf_file.close()

    counter = 0
    for i in range(0, len(rules)):
        if rules[i] in iptables_rules:
            counter += 1

    if counter == len(rules):
        return True
    else:
        return False

def updateIptablesRules(old_rules, new_rules):
    if len(old_rules) == len(new_rules):
        iptables_conf_file = open("conf/wall_iptables.conf", "rb")
        iptables_rules = iptables_conf_file.read()
        iptables_conf_file.close()

        iptables_conf_file = open("conf/wall_iptables.conf", "wb")

        for i in range(0, len(old_rules)):
            iptables_rules = iptables_rules.replace(old_rules[i], new_rules[i])

        iptables_conf_file.write(iptables_rules)
        iptables_conf_file.close()

        print "[*] Updating iptables rules..."
        system("iptables-restore < conf/wall_iptables.conf")
        print "[*] Rules updated!"

    else:
        print "[!] Error during iptables rules update"

def statusCheck(option_name, option_status, ask):
    choice = ""

    try:
        if ask == True:
            if option_status == True:
                print "\n[*] %s is currently: \033[1;32mENABLED\033[0m" % (option_name)
                choice = raw_input("Do you want to disable it? [Y/n] ")
            else:
                print "\n[*] %s is currently: \033[1;31mDISABLED\033[0m" % (option_name)
                choice = raw_input("Do you want to enable it? [Y/n] ")
        else:
            if option_status == True:
                print "[*] %s is currently: \033[1;32mENABLED\033[0m" % (option_name)
            else:
                print "[*] %s is currently: \033[1;31mDISABLED\033[0m" % (option_name)
    except:
        print "\n[!] Unexpected error"

    return choice

def main():
    splashcreen()

    http_filter = HttpConnectionsFilter()
    invalid_packets_filter = InvalidPacketsFilter()
    general_filter = GeneralPurposeFilter()
    adsmasher = AdSmasher()
    gitm = Gitm()

    http_filter_process = Process(target=http_filter.start)
    invalid_packets_filter_process = Process(target=invalid_packets_filter.start)
    general_filter_process = Process(target=general_filter.start)
    gitm_process = Process(target=gitm.start)
    adsmasher_process = Process(target=adsmasher.start)

    try:
        while True:
            http_filter_enabled = checkIptablesRules(["-A PREROUTING -i br0 -p tcp -m tcp --dport 80 -j NFQUEUE --queue-num 1"])
            invalid_packets_filter_enabled = checkIptablesRules(["-A FORWARD -m state --state INVALID -j NFQUEUE --queue-num 2", "-A FORWARD -m state --state INVALID -j NFQUEUE --queue-num 2", "-A FORWARD -m state --state INVALID -j NFQUEUE --queue-num 2"])
            general_filter_enabled = checkIptablesRules(["-A FORWARD -j NFQUEUE --queue-num 3", "-A FORWARD -j NFQUEUE --queue-num 3", "-A FORWARD -j NFQUEUE --queue-num 3"])
            adsmasher_enabled = checkIptablesRules(["-A PREROUTING -i br0 -p udp -m udp --dport 53 -j NFQUEUE --queue-num 8"])
            gitm_enabled = False

            onion_routing_rules = ["-A PREROUTING -i br0 -p tcp -m tcp --dport 51150 -j ACCEPT", "-A PREROUTING -i br0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 9095", "-A PREROUTING -i br0 -p tcp -j REDIRECT --to-ports 9090"]
            current_rules = check_output("iptables-save")
            counter = 0
            for i in range(0, len(onion_routing_rules)):
                if onion_routing_rules[i] in current_rules:
                    counter += 1
            onion_routing_enabled = (counter == len(onion_routing_rules))

            try:
                open("features/gitm/.gitm.lock", "rb").close()
                gitm_enabled = True
            except IOError as ex:
                if ex.errno == 2:
                    gitm_enabled = False

            print
            print "Available options:"
            print "   1) Filter clear text HTTP connections"
            print "   2) Filter invalid sessions's packets"
            print "   3) Filter all packets which don't respect any iptables rule"
            print "   4) Guardian-in-the-middle feature"
            print "   5) Ad-blocking feature"
            print "   6) Onion routing"
            print "   7) Services status check"
            print "  98) Clear the screen"
            print "  99) Quit filters manager"
            print

            try:
                option = input("Option: ")

                if option <= 7 or option == 98 or option == 99:
                    if option == 1:
                        response = statusCheck("HTTP connections filter", http_filter_enabled, True)

                        if http_filter_enabled == True and response == "Y":
                            updateIptablesRules(["-A PREROUTING -i br0 -p tcp -m tcp --dport 80 -j NFQUEUE --queue-num 1"], ["-A PREROUTING -i br0 -p tcp -m tcp --dport 80 -j ACCEPT"])
                            http_filter_enabled = False
                            http_filter_process.terminate()
                            http_filter_process = Process(target=http_filter.start)

                        elif http_filter_enabled == False and response == "Y":
                            updateIptablesRules(["-A PREROUTING -i br0 -p tcp -m tcp --dport 80 -j ACCEPT"], ["-A PREROUTING -i br0 -p tcp -m tcp --dport 80 -j NFQUEUE --queue-num 1"])
                            http_filter_enabled = True
                            http_filter_process.start()

                        elif response.lower() == "n" or response == "":
                            print "[*] Filter status unchanged"

                        else:
                            print "[!] Invalid choice"

                    elif option == 2:
                        print "[*] Work in progress"

                    elif option == 3:
                        #general_filter_process.start()
                        print "[*] Work in progress"

                    elif option == 4:
                        response = statusCheck("Guardian-in-the-middle feature", gitm_enabled, True)

                        if gitm_enabled == True and response == "Y":
                            gitm_enabled = False
                            gitm_process.terminate()
                            gitm_process = Process(target=gitm.start)

                        elif gitm_enabled == False and response == "Y":
                            gitm_enabled = True
                            gitm_process.start()

                    elif option == 5:
                        response = statusCheck("Ad-blocking feature", adsmasher_enabled, True)

                        if adsmasher_enabled == True and response == "Y":
                            updateIptablesRules(["-A PREROUTING -i br0 -p udp -m udp --dport 53 -j NFQUEUE --queue-num 8"], ["-A PREROUTING -i br0 -p udp -m udp --dport 53 -j ACCEPT"])
                            adsmasher_enabled = False
                            adsmasher_process.terminate()
                            adsmasher_process = Process(target=adsmasher.start)

                        elif adsmasher_enabled == False and response == "Y":
                            updateIptablesRules(["-A PREROUTING -i br0 -p udp -m udp --dport 53 -j ACCEPT"], ["-A PREROUTING -i br0 -p udp -m udp --dport 53 -j NFQUEUE --queue-num 8"])
                            adsmasher_enabled = True
                            adsmasher_process.start()

                        elif response.lower() == "n" or response == "":
                            print "[*] Feature status unchanged"

                        else:
                            print "[!] Invalid choice"

                    elif option == 6:
                        response = statusCheck("Onion routing", onion_routing_enabled, True)

                        if onion_routing_enabled == True and response == "Y":
                            system("bridge_ip=$(ifconfig br0 | grep \"inet\" | expand | tr -s \" \" | grep -v \"inet6\" | cut -d \" \" -f 3) && iptables -t nat -D PREROUTING -i br0 -d $bridge_ip -j ACCEPT")
                            system("iptables -t nat -D PREROUTING -i br0 -p tcp --destination-port 51150 -j ACCEPT")
                            system("iptables -t nat -D PREROUTING -i br0 -p udp --destination-port 53 -j REDIRECT --to-port 9095")
                            system("iptables -t nat -D PREROUTING -i br0 -p tcp -j REDIRECT --to-port 9090")
                            #system("systemctl stop tor.service")
                            onion_routing_enabled = False
                            print "[*] Onion routing disabled!"

                        elif onion_routing_enabled == False and response == "Y":
                            system("bridge_ip=$(ifconfig br0 | grep \"inet\" | expand | tr -s \" \" | grep -v \"inet6\" | cut -d \" \" -f 3) && iptables -t nat -A PREROUTING -i br0 -d $bridge_ip -j ACCEPT")
                            system("iptables -t nat -A PREROUTING -i br0 -p tcp --destination-port 51150 -j ACCEPT")
                            system("iptables -t nat -A PREROUTING -i br0 -p udp --destination-port 53 -j REDIRECT --to-port 9095")
                            system("iptables -t nat -A PREROUTING -i br0 -p tcp -j REDIRECT --to-port 9090")
                            #system("systemctl start tor.service")
                            onion_routing_enabled = True
                            print "[*] Onion routing enabled!"

                        elif response.lower() == "n" or response == "":
                            print "[*] Onion routing status unchanged"

                    elif option == 7:
                        # For latency problems you have to check once again for the presence of the features/gitm/.gitm.lock file
                        gitm_enabled = False

                        try:
                            open("features/gitm/.gitm.lock", "rb").close()
                            gitm_enabled = True
                        except IOError as ex:
                            if ex.errno == 2:
                                gitm_enabled = False

                        print
                        statusCheck("HTTP connections filter", http_filter_enabled, False)
                        statusCheck("Invalid packets filter", invalid_packets_filter_enabled, False)
                        statusCheck("General purpose filter", general_filter_enabled, False)
                        statusCheck("Guardian-in-the-middle feature", gitm_enabled, False)
                        statusCheck("Ad-blocking feature", adsmasher_enabled, False)
                        statusCheck("Onion routing", onion_routing_enabled, False)

                    elif option == 98:
                        splashcreen()

                    elif option == 99:
                        print "[*] Disabling all enabled features..."

                        if http_filter_enabled == True and http_filter_process.is_alive() == True:
                            updateIptablesRules(["-A PREROUTING -i br0 -p tcp -m tcp --dport 80 -j NFQUEUE --queue-num 1"], ["-A PREROUTING -i br0 -p tcp -m tcp --dport 80 -j ACCEPT"])
                            http_filter_process.terminate()

                        if general_filter_enabled == True and general_filter_process.is_alive() == True:
                            general_filter_process.terminate()

                        if gitm_enabled == True and gitm_process.is_alive() == True:
                            gitm_process.terminate()

                        if adsmasher_enabled == True and adsmasher_process.is_alive() == True:
                            updateIptablesRules(["-A PREROUTING -i br0 -p udp -m udp --dport 53 -j NFQUEUE --queue-num 8"], ["-A PREROUTING -i br0 -p udp -m udp --dport 53 -j ACCEPT"])
                            adsmasher_process.terminate()

                        if onion_routing_enabled == True:
                            system("bridge_ip=$(ifconfig br0 | grep \"inet\" | expand | tr -s \" \" | grep -v \"inet6\" | cut -d \" \" -f 3) && iptables -t nat -D PREROUTING -i br0 -d $bridge_ip -j ACCEPT")
                            system("iptables -t nat -D PREROUTING -i br0 -p tcp --destination-port 51150 -j ACCEPT")
                            system("iptables -t nat -D PREROUTING -i br0 -p udp --destination-port 53 -j REDIRECT --to-port 9095")
                            system("iptables -t nat -D PREROUTING -i br0 -p tcp -j REDIRECT --to-port 9090")
                            #system("systemctl stop tor.service")

                        print "[*] Restoring previous iptables configuration..."
                        system("iptables-restore < old/iptables_config.old")

                        break
                else:
                    raise ValueError
            except ValueError:
                print "[!] Invalid option\n"
            except SyntaxError:
                print "[!] Invalid option\n"

    except KeyboardInterrupt:
            print

try:
    main()
    sys.exit(0)
except OSError:
    print "[!] You need to be root to run FiltersManager.py"
