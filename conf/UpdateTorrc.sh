#!/bin/bash

bridge_ip=$(ifconfig br0 | grep "inet" | expand | tr -s " " | grep -v "inet6" | cut -d " " -f 3)
sed -i "s/^TransPort.*9090$/TransPort $bridge_ip:9090/" /etc/tor/torrc
systemctl restart tor.service
