#! /bin/sh

# Location of nft in your system
$NFT=`which nft`

#################################################################
# Enabling Kernel-Monitoring Support

# Enable broadcast echo Protection to ignore an echo request
# to a broadcast address thus preventing compromising all host
# at one time
echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Disable Source Routed Packages
# source routing, also called path addressing,allows a sender
# of a packet to partially or completely specify the route the
# packet takes through the network
echo "0" > /proc/sys/net/ipv4/conf/all/accept_source_route

# Enable TCP SYN Cookie Protection
# Protect against SYN Flooding Attack
echo "1" > /proc/sys/net/ipv4/tcp_syncookies

# Disable ICMP Redirect Acceptance
echo "0" > /proc/sys/net/ipv4/conf/all/accept_redirects

# Do not send ICMP redirect messages
echo "0" > /proc/sys/net/ipv4/conf/all/send_redirects

# Drop Spoofed Packets coming in on an interface ,which , if
# replied to, would result in the reply going out a different
# interface
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo "1" > f
done

# Log packets with impossible addresses (address 0.0.0.0,
# host 0 on any network ,any host on 127 network and Class
# E network)
echo "1" > /proc/sys/net/ipv4/conf/all/log_martians


#################################################################
# Removing all existing chains from filter table
# $NFT flush table <table_name>
for i in `$NFT list tables | awk 'print $2'`
do
	echo "Flushing ${i}"
	$NFT flush table ${i}
	for j in `$NFT list table ${i} | grep chain | awk 'print $2'`
	do
		echo "...Deleting chain ${j} from table ${i}"
		$NFT delete chain ${i} ${j}
	done
	echo "Deleting table ${i}"
	$NFT delete table ${i}
done


#################################################################
# Re-create default table and chains
$NFT -f setup-tables
$NFT -f localhost-policy
$NFT -f connectionstate-policy

$NFT -f invalid-policy
$NFT -f dns-policy

$NFT -f tcp-client-policy
$NFT -f tcp-server-policy

$NFT -f icmp-policy

$NFT -f log-policy
# Default drop policy
$NFT -f default-policy
