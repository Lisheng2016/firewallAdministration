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
$IPT --flush

# use -t to specify tables to flush
# $IPT -F -t nat
# $IPT -F -t mangle

# Deleting all user-defined chains
for tables in filter nat mangle
do 
	$IPT -t ${tables} -X
done
################ Removing Any Preexisting Rules ####################


################ Resetting Default Policies  ####################
for table in filter nat mangle
do
	case ${table} in
		filter)
			for chain in INPUT OUTPUT FORWARD
			do
				$IPT -t ${table} -P ${chain} ACCEPT
			done
		;;

		nat)
			for chain in PREROUTING FORWARD POSTROUTING
			do
				$IPT -t ${table} -P ${chain} ACCEPT
			done
		;;

		mangle)
			for chain in PREROUTING OUTPUT
			do
				$IPT -t ${table} -P ${chain} ACCEPT
			done
		;;

		*)
			echo "Illegal Usage!"
			exit 1
		;;

	esac
done
################ Resetting Default Policies  ####################


#############################  Main  ############################

# Unlimit traffic on the loopback interface
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# Set the default policy to Drop
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

# Using Conntrack to bypass rule checking
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -m state --state INVALID -j LOG \
		--log-prefix "INVALID input: "
$IPT -A INPUT -m state --state INVALID -j DROP
$IPT -A OUTPUT -m state --state INVALID -j LOG \
		--log-prefix "INVALID output: "
$IPT -A OUTPUT -m state --state INVALID -j DROP

# Refuse spoofed packets pretending to be from ipaddr of server's 
# ethernet adaptor
$IPT -A INPUT -i $INTERNET -s $IPADDR -j DROP

# There is no need to block outgoing packet's destinating for yourself 
# as it will be sent to lo interface anyway,this is to say,the packet 
# sent from your machine and to your machine never reaches external 
# interface

# Refuse packets claiming to be from CLASS_A,CLASS_B and CLASS_C 
# private network
$IPT -A INPUT -i $INTERNET -s $CLASS_A -j DROP
$IPT -A INPUT -i $INTERNET -s $CLASS_B -j DROP
$IPT -A INPUT -i $INTERNET -s $CLASS_C -j DROP

# Refuse packages claiming from loopback interfaces
$IPT -A INPUT -i $INTERNET -s $LOOPBACK -j DROP

# Refuse malformed broadcast packets
$IPT -A INPUT -i $INTERNET -s $BROADCAST_DEST -j LOG
$IPT -A INPUT -i $INTERNET -s $BROADCAST_DEST -j DROP
$IPT -A INPUT -i $INTERNET -d $BROADCAST_SRC -j LOG
$IPT -A INPUT -i $INTERNET -d $BROADCAST_SRC -j LOG

# Refuse directed broadcasts used to map networks and form
# DOS attacks
$IPT -A INPUT -i $INTERNET -d $SUBNET_BASE -j DROP
$IPT -A INPUT -i $INTERNET -d $SUBNET_BROADCAST -j DROP

# Refuse CLASS_D multicast address
# Illegal as soure address
$IPT -A INPUT -i $INTERNET -s $CLASS_D_MULTICAST -j DROP

# Legitimate multicast packets are always UDP packets
# Refuse any not-udp packets to CLASS_D_MULTICAST address
$IPT -A INPUT -i $INTERNET ! -p udp -d $CLASS_D_MULTICAST -j DROP

# Accept incoming multicast packets
$IPT -A INPUT -i $INTERNET -p udp -d $CLASS_D_MULTICAST -j ACCEPT

# Refuse packets from CLASS_E address
$IPT -A INPUT -i $INTERNET -s $CLASS_E_RESERVED_NET -j DROP






