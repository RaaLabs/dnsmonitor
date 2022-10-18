#!/bin/bash

# sleep 10

## If running shell scripts to start the service is needed,
## use something like the example below, and call this run.sh
## script via systemd.

/bin/bash -c 'CAPTURENIC=$(nmcli conn |grep "WAN"|awk "{print \$4}")  && /usr/local/dnsmonitor/dnsmonitor -iface=${CAPTURENIC}'
