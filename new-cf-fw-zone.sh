#!/bin/bash
#/etc/nginx/scripts/new-cf-fw-zone.sh
#v0.1

readonly LOG_FILE="/var/log/messages"
readonly FIREWALLD_ZONE="cloudflare"

# Create the cloudflare zone and populate it.
sudo /usr/bin/firewall-cmd --info-zone="$FIREWALLD_ZONE" > /dev/null 2>&1
FIREWALLD_EXIT_CODE=$?
if [ $FIREWALLD_EXIT_CODE -eq 0 ]
then
        echo "$(date) $0: FirewallD exit code $FIREWALLD_EXIT_CODE - $FIREWALLD_ZONE zone already exists!"
        echo "Nothing to do here, exiting."
        exit 1
else
        sudo firewall-cmd --new-zone="$FIREWALLD_ZONE" --permanent > /dev/null 2>&1
        sudo firewall-cmd --zone="$FIREWALLD_ZONE" --set-target=DROP --permanent > /dev/null 2>&1
        sudo firewall-cmd --zone="$FIREWALLD_ZONE" --add-service=http --permanent > /dev/null 2>&1
        sudo firewall-cmd --zone="$FIREWALLD_ZONE" --add-service=https --permanent > /dev/null 2>&1
        sudo firewall-cmd --new-ipset=cloudflare-ipv4 --type=hash:net --option=family=inet --permanent > /dev/null 2>&1
        sudo firewall-cmd --new-ipset=cloudflare-ipv6 --type=hash:net --option=family=inet6 --permanent > /dev/null 2>&1
        sudo firewall-cmd --zone="$FIREWALLD_ZONE" --add-source=ipset:cloudflare-ipv4 --permanent > /dev/null 2>&1
        sudo firewall-cmd --zone="$FIREWALLD_ZONE" --add-source=ipset:cloudflare-ipv6 --permanent > /dev/null 2>&1
        sudo firewall-cmd --reload > /dev/null 2>&1
        sudo firewall-cmd --info-zone="$FIREWALLD_ZONE"
fi
