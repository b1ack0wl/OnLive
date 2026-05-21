#!/bin/sh
# usage: exec_wifi_boot.sh <ifname> <ssid> <passphrase>
# ifname = interface name (in this case mlan0)

#Kill current connection
ifdown $1

iwpriv $1 passphrase "1;ssid=$2;passphrase=$3"
iwconfig $1 essid $2

ifup $1 inet dhcp

