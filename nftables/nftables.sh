# import constants
source Constants.sh

################ Enabling Kernel-Monitoring Support ################

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

################ Enabling Kernel-Monitoring Support ################


################ Removing Any Preexisting Rules ####################
# Removing all existing rules from all chains
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
################ Removing Any Preexisting Rules ####################


############### Re-create default table and chains #################
$NFT -f setup-tables.sh

############### Re-create default table and chains #################


#############################  Main  ############################
$NFT add rule filter input iifname lo accept 
$NFT add rule filter output oifname lo accept

# Using conntrack to bypass already established or related traffic
$NFT add rule filter input ct state established,related accept
$NFT add rule filter input ct state invalid log prefix \"INVALID input: \" limit 
 rate 3/second drop
$NFT add rule filter output ct state established,related accept
$NFT add rule filter output ct state invalid log prefix \"INVALID output: \" limit
 rate 3/second drop


# Refuse spoofed packets pretending to be from ipaddr of server's 
# ethernet adaptor
$NFT add rule filter input iifname $INTERNET ip saddr $IPADDR

# There is no need to block outgoing packet's destinating for yourself 
# as it will be sent to lo interface anyway,this is to say,the packet 
# sent from your machine and to your machine never reaches external 
# interface

# Reject packages claiming to be from CLASS_A,CLASS_B and CLASS_C 
# private network
$NFT add rule filter input iifname $INTERNET ip saddr $CLASS_A drop
$NFT add rule filter input iifname $INTERNET ip saddr $CLASS_B drop
$NFT add rule filter input iifname $INTERNET ip saddr $CLASS_C drop

# Reject packages claiming from loopback interfaces
$NFT add rule filter input iifname $INTERNET ip saddr $LOOPBACK drop

# Reject malformed broadcast packages
$NFT add rule filter input iifname $INTERNET ip saddr $BROADCAST_DEST \
 log prefix \"With 255.255.255.255 as source: \" limit rate 3/second drop
$NFT add rule filter input iifname $INTERNET ip saddr $BROADCAST_SRC \
 log prefix \"With 0.0.0.0 as destination: \" limit rate 3/second drop

# Refuse directed broadcasts used to map networks and form
# DOS attacks
$NFT add rule filter input iifname $INTERNET ip daddr $SUBNET_BASE drop
$NFT add rule filter input iifname $INTERNET ip daddr $SUBNET_BROADCAST drop

# Refuse CLASS_D multicast address
# Illegal as soure address
$NFT add rule filter input iifname $INTERNET ip saddr $CLASS_D_MULTICAST drop

# Legitimate multicast packets are always UDP packets
# Refuse any not-udp packets to CLASS_D_MULTICAST address
$NFT add rule filter input iifname $INTERNET ip daddr $CLASS_D_MULTICAST ip protocol \
!= udp drop

# Accept incoming multicast packets
$NFT add rule filter input iifname $INTERNET ip daddr $CLASS_D_MULTICAST ip protocol \
udp accept

# Refuse packets from CLASS_E address
$NFT add rule filter input iifname $INTERNET ip saddr $CLASS_E_RESERVED_NET drop