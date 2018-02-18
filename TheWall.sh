#!/bin/bash

# TODO:
#   + Detect port scanning attack
#   + Log frequent packets senders in order to mitigate potential DoS attacks
#   + Log ICMP echo-requests packets and the packet's source IP
#   + Warn the user when HTTP connections are established instead of HTTPS
#   - Warn the user when a process different from web browser is trying to access the web (monitoring output of 'lsof -i' or content of /proc/net/tcp)
#   + Enable IP blacklist/whitelist support
#   + Configure and enable hostapd.service and dnsmasq.service to act as a firewall/gateway (only for hardware firewall!)
#   - Enable VPN for every connection
#   - Enable onion routing only for listed IPs

clear

echo -e "[*] Starting firewall configuration...\n"

echo "[*] Configuring bridge..."

# Bridge setup (Raspberry Pi)
modprobe br_netfilter && echo '1' > /proc/sys/net/bridge/bridge-nf-call-iptables

#echo "[*] Setting up hostapd.service..."

# Set up hostapd.service and related configuration file

#echo "[*] Establishing VPN connection..."

# Configure OpenVPN connection
#openvpn conf/openvpn/nl-free-01.protonvpn.com.udp1194.ovpn &> /dev/null

echo "[*] Enabling packet forwarding..."

# Enable packet forwarding
echo '1' > /proc/sys/net/ipv4/ip_forward

echo "[*] Backing up current iptables configuration..."

# Back up current iptables configuration
iptables-save > /home/pi/TheWall/old/iptables_config.old

echo "[*] Flushing iptables chains..."

# Flush every iptables chain content and delete every user-defined chain
iptables -t filter -F
iptables -t filter -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

echo "[*] Setting up onion routing..."

# Enable onion routing
bridge_ip=$(ifconfig br0 | grep "inet" | expand | tr -s " " | grep -v "inet6" | cut -d " " -f 3)

if [[ ! -e /tmp/.torrc_updated ]] || [[ $(stat -c "%u" /tmp/.torrc_updated) != "0" ]]; then
  rm -f /tmp/.torrc_updated &> /dev/null
  sed -i.orig "s/^DNSPort.*9095$/DNSPort $bridge_ip:9095/" /etc/tor/torrc
  sed -i.orig "s/^TransPort.*9090$/TransPort $bridge_ip:9090/" /etc/tor/torrc
  systemctl restart tor.service
  touch /tmp/.torrc_updated
fi

iptables -t nat -A PREROUTING -i br0 -d $bridge_ip -j ACCEPT
iptables -t nat -A PREROUTING -i br0 -p tcp --destination-port 51150 -j ACCEPT

for i in $(cat conf/not_torify.conf); do
  iptables -t nat -A PREROUTING -i br0 -s $i -j ACCEPT
done

iptables -t nat -A PREROUTING -i br0 -p udp --destination-port 53 -j REDIRECT --to-port 9095
iptables -t nat -A PREROUTING -i br0 -p tcp -j REDIRECT --to-port 9090

echo "[*] Setting up IP blacklist..."

# Set up IP blacklist
for i in $(cat conf/ip_blacklist.conf); do
  iptables -t filter -A FORWARD -s $i -j DROP
  iptables -t filter -A FORWARD -d $i -j DROP
done

echo "[*] Setting up IP whitelist..."

# Set up IP whitelist
for i in $(cat conf/ip_whitelist.conf); do
  iptables -t filter -A FORWARD -s $i -j ACCEPT
  iptables -t filter -A FORWARD -d $i -j ACCEPT
done

echo "[*] Configuring iptables rules..."

# Mangle table
iptables -t mangle -A PREROUTING -i br0 -p tcp --dport 80 -j ACCEPT
iptables -t mangle -A PREROUTING -i br0 -p udp --dport 53 -j ACCEPT

# Set default policy to 'DROP' for filter table
iptables -t filter -P FORWARD DROP

# Permit new hosts connections
iptables -A FORWARD -s 192.168.1.1 -j ACCEPT
iptables -A FORWARD -d 255.255.255.255 -p udp -j ACCEPT

# Allow traffic on loopback interface
iptables -t filter -A INPUT -i lo -j ACCEPT
iptables -t filter -A OUTPUT -o lo -j ACCEPT

# Allow HTTP connections but warns the user
iptables -t filter -A FORWARD -p tcp --destination-port 80 -j ACCEPT

# Allow HTTPS connections
iptables -t filter -A FORWARD -p tcp --destination-port 443 -j ACCEPT

# Allow DNS requests and responses
iptables -t filter -A FORWARD -p udp --destination-port 53 -j ACCEPT

# Allow FTP connections
iptables -t filter -A FORWARD -p tcp -m multiport --destination-ports 20,21 -j ACCEPT

# Allow SSH connections
iptables -t filter -A FORWARD -p tcp --destination-port 22 -j ACCEPT

# Allow OpenVPN packets for ProtonVPN's UDP connections
iptables -t filter -A FORWARD -p udp --destination-port 1194 -j ACCEPT

# Allow SMTP connections
iptables -t filter -A FORWARD -p tcp -m multiport --destination-ports 25,465 -j ACCEPT

# Allow IMAP connections
iptables -t filter -A FORWARD -p tcp -m multiport --destination-ports 143,993 -j ACCEPT

# Allow POP3 connections
iptables -t filter -A FORWARD -p tcp -m multiport --destination-ports 110,995 -j ACCEPT

# Allow specific services
iptables -t filter -A FORWARD -p tcp -m multiport --destination-ports 5222,5228,9339 -j ACCEPT
iptables -t filter -A FORWARD -p udp -m multiport --destination-ports 5353,443,5055,5056 -j ACCEPT

# Detect and mitigate potential port scanning or DoS attacks
iptables -t filter -A FORWARD -p tcp -m multiport ! --source-ports 20,21,22,25,80,110,143,443,465,993,995,9050,9151 -m recent --name BLACKLIST --set
iptables -t filter -A FORWARD -p tcp -m multiport ! --source-ports 20,21,22,25,80,110,143,443,465,993,995,9050,9151 -m recent --name BLACKLIST --seconds 3 -m limit --limit 10/min --update -j LOG --log-prefix "TCP packet dropped: " --log-level 4
iptables -t filter -A FORWARD -p tcp -m multiport ! --source-ports 20,21,22,25,80,110,143,443,465,993,995,9050,9151 -m recent --name BLACKLIST --seconds 3 --update -j DROP
iptables -t filter -A FORWARD -p udp -m multiport ! --source-ports 53,1194 -m recent --name BLACKLIST --set
iptables -t filter -A FORWARD -p udp -m multiport ! --source-ports 53,1194 -m recent --name BLACKLIST --seconds 3 --update -m limit --limit 10/min -j LOG --log-prefix "UDP packet dropped: " --log-level 4
iptables -t filter -A FORWARD -p udp -m multiport ! --source-ports 53,1194 -m recent --name BLACKLIST --seconds 3 --update -j DROP
iptables -t filter -A FORWARD -p tcp -m multiport ! --source-ports 20,21,22,25,80,110,143,443,465,993,995,9050,9151 -m recent --name BLACKLIST --remove -j ACCEPT
iptables -t filter -A FORWARD -p udp -m multiport ! --source-ports 53,1194 -m recent --name BLACKLIST --remove -j ACCEPT

# Filter invalid packets
iptables -t filter -A FORWARD -m state --state INVALID -j NFQUEUE --queue-num 2

# Filter all other packets
iptables -t filter -A FORWARD -j NFQUEUE --queue-num 3

echo "[*] Generating configuration file..."

# Backup iptables configuration
iptables-save > /home/pi/TheWall/conf/wall_iptables.conf

echo -e "\n[*] The firewall has been set up!"

# Starting filters manager
python2 FiltersManager.py
