#!/bin/bash
#/etc/nginx/scripts/get-cf-ips.sh
#v0.1

readonly LOG_FILE="/var/log/messages"
readonly NGINX_CF_CONFIG_FILE="/etc/nginx/conf-available/1-cloudflare.conf"
readonly FIREWALLD_ZONE="cloudflare"

# The URLs with the actual IP addresses used by CloudFlare.
CF_URL_IPV4="https://www.cloudflare.com/ips-v4/"
CF_URL_IPV6="https://www.cloudflare.com/ips-v6/"

# Location of th  IPv4 and IPv6 text files.
CF_IPV4_LIST_FILE="/etc/nginx/cloudflare/ipv4-list.txt"
CF_IPV6_LIST_FILE="/etc/nginx/cloudflare/ipv6-list.txt"

# Check if curl and wget are installed.
if [ ! -f /usr/bin/curl ] || [ ! -f /usr/bin/wget ]
then
        echo "$(date) $0: Unable to download CloudFlare files." >> $LOG_FILE
        exit 1
fi

# Check if there has been a change in IPv4 or IPv6 address ranges. Exit if there hasn't been any change.
if [ -f $CF_IPV4_LIST_FILE ] && [ -f $CF_IPV6_LIST_FILE ]
then
        ipv4_local_checksum=$(cat $CF_IPV4_LIST_FILE | md5sum)
        ipv6_local_checksum=$(cat $CF_IPV6_LIST_FILE | md5sum)
        ipv4_cf_checksum=$(curl --silent $CF_URL_IPV4 | md5sum)
        ipv6_cf_checksum=$(curl --silent $CF_URL_IPV6 | md5sum)
if [ "$ipv4_local_checksum" = "$ipv4_cf_checksum" ] && [ "$ipv6_local_checksum" = "$ipv6_cf_checksum" ]
then
        exit 1
fi
fi

# Download the CloudFlare IP address ranges files.
if [ -f /usr/bin/curl ]
then
        curl --silent --output $CF_IPV4_LIST_FILE $CF_URL_IPV4
        curl --silent --output $CF_IPV6_LIST_FILE $CF_URL_IPV6
        chown root:nginx $CF_IPV4_LIST_FILE
        chmod 0640 $CF_IPV4_LIST_FILE
        chown root:nginx $CF_IPV6_LIST_FILE
        chmod 0640 $CF_IPV6_LIST_FILE
elif [ -f /usr/bin/wget ]
then
        wget --quiet --output-document=$CF_IPV4_LIST_FILE --no-check-certificate $CF_URL_IPV4
        wget --quiet --output-document=$CF_IPV6_LIST_FILE --no-check-certificate $CF_URL_IPV6
        chown root:nginx $CF_IPV4_LIST_FILE
        chmod 0640 $CF_IPV4_LIST_FILE
        chown root:nginx $CF_IPV6_LIST_FILE
        chmod 0640 $CF_IPV6_LIST_FILE
fi

# Update firewalld cloudflare zone ips.
sudo /usr/bin/firewall-cmd --info-zone="$FIREWALLD_ZONE" > /dev/null 2>&1
FIREWALLD_EXIT_CODE=$?
if [ $FIREWALLD_EXIT_CODE -eq 112 ]
then
        echo "$(date) $0: FirewallD exit code $FIREWALLD_EXIT_CODE - $FIREWALLD_ZONE zone does not exist!" >> $LOG_FILE
else
        sudo /usr/bin/firewall-cmd --ipset=cloudflare-ipv4 --add-entries-from-file=$CF_IPV4_LIST_FILE --permanent > /dev/null 2>&1
        sudo /usr/bin/firewall-cmd --ipset=cloudflare-ipv6 --add-entries-from-file=$CF_IPV6_LIST_FILE --permanent > /dev/null 2>&1
        sudo /usr/bin/firewall-cmd --reload > /dev/null 2>&1
fi

# Generate the new nginx cloudflare.conf config file.
NGINX_CF_CONFIG_FILE_CONTENT="# CloudFlare IP address ranges generated on $(date) by $0 \n"
NGINX_CF_CONFIG_FILE_CONTENT+="\n"
NGINX_CF_CONFIG_FILE_CONTENT+="# IPv4 ranges - downloaded from $CF_URL_IPV4 \n"
NGINX_CF_CONFIG_FILE_CONTENT+=$(awk '{ printf "set_real_ip_from " $0";\\n" }' $CF_IPV4_LIST_FILE)
NGINX_CF_CONFIG_FILE_CONTENT+="\n"
NGINX_CF_CONFIG_FILE_CONTENT+="# IPv6 ranges - downloaded from $CF_URL_IPV6 \n"
NGINX_CF_CONFIG_FILE_CONTENT+=$(awk '{ printf "set_real_ip_from " $0";\\n" }' $CF_IPV6_LIST_FILE)
NGINX_CF_CONFIG_FILE_CONTENT+="\n"
NGINX_CF_CONFIG_FILE_CONTENT+="real_ip_header CF-Connecting-IP;\n"
NGINX_CF_CONFIG_FILE_CONTENT+="\n"

echo -e $NGINX_CF_CONFIG_FILE_CONTENT > $NGINX_CF_CONFIG_FILE

# Test the nginx configuration.
( $(sudo /usr/sbin/nginx -t) ) > /dev/null 2>&1
if [ $? ]
then
        echo "$(date) $0: CloudFlare IP ranges have been updated @ $NGINX_CF_CONFIG_FILE" >> $LOG_FILE
# Reload the nginx configiguration.
( $(systemctl reload nginx) ) > /dev/null 2>&1
else
        echo "$(date) $0: The configuration file $NGINX_CF_CONFIG_FILE or /etc/nginx/nginx.conf syntax are not valid, please check. The nginx web server did not load the new configuration." >> $LOG_FILE
fi
