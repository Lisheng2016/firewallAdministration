#! /bin/sh
INTERNET="eth0"							# Internet-connected interface
LOOPBACK_INTERFACE="lo"					# Loopback interface name
IPADDR="my.ip.address"					# IP address of the internet-connnected interface
MY_ISP="my.isp.address.range"			# ISP server & NOC address range
SUBNET_BASE="my.subnet.network"			# Your subnet's network address
SUBNET_BROADCAST="my.subnet.bcast"		# Your subnet's broadcast address
LOOPBACK="127.0.0.0/8"					# Reserved loopback address range
CLASS_A="10.0.0.0/8"					# Class A private networks
CLASS_B="172.16.0.0/12"					# Class B private networks
CLASS_C="192.168.0.0/16"				# Class C private networks
CLASS_D_MULTICAST="224.0.0.0/5"			# Class D multicast address
CLASS_E_RESERVED_NET="240.0.0.0/5"		# Class E reserved address
BROADCAST_SRC="0.0.0.0"					# Broadcast source address
BROADCAST_DEST="255.255.255.255"		# Broadcast destination address
PRIVPORTS="0:1023"						# Well-known, privileged port range
UNPRIVPORTS="1024:65535"				# Unprivileged port range
XWINDOW_PORTS="6000:6063"   			# (TCP) X Windows
NFS_PORT="2049"							# (TCP) NFS
LOCKD_PORT="4045"						# (TCP) RPC LOCKD for NFS
SOCKS_PORT="1080"						# (TCP) SOCKS
OPENWINDOWS_PORT="2000"					# (TCP) OpenWindows
SQUID_PORT="3128"						# (TCP) Squid


# Location of iptables on your system
IPT=`which iptables`

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

# Refuse spoofed packets pretending to be from IPADDR of server's 
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

# X Window connection establishment
# Refuse initializing from server to other machine
$IPT -A OUTPUT -o $INTERNET -p tcp --syn --destination-port=$XWINDOWS_PORTS -j REJECT

# Refuse all incoming establishment attemps to XWindows as all X traffic should
# be tunnelled through SSH
$IPT -A INPUT -i $INTERNET -p tcp --destination-port=$XWINDOWS_PORTS -m state --state=new -j DROP


# Establising a connection over TCP to NFS, OpenWindows, Squid, or SOCKS

$IPT -A INPUT -i $INTERNET -p tcp \
-m multiport --destination-port \
$NFS_PORT,$OPENWINDOWS_PORT,$SQUID_PORT,$SOCKS_PORT \
--syn -j DROP

$IPT -A OUTPUT -o $INTERNET -p tcp \
-m multiport --destination-port \
$NFS_PORT,$OPENWINDOWS_PORT,$SQUID_PORT,$SOCKS_PORT \
--syn -j REJECT


# NFS and RPC lockd
$IPT -A INPUT -i $INTERNET -p udp \
-m multiport --destination-port \
$NFS_PORT,$LOCKD_PORT -j DROP

$IPT -A OUTPUT -o $INTERNET -p udp \
-m multiport --destination-port \
$NFS_PORT,$LOCKD_PORT -j REJECT


# Allowing DNS Lookups as a Client
isConntrack=`lsmod | grep ^nf_conntrack_ipv4 | awk '{print $1}'`
NAMESEVER="my.name.server"			# (TCP/UDP) DNS

if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	$IPT -A OUTPUT -o $INTERNET -p udp \
	-s $IPADDR --sport $UNPRIVPORTS \
	-d $NAMESEVER --dport 53 \
	-m state --state NEW -j ACCEPT
fi

# Conntrack unavailable or not installed
# as is static rules
$IPT -A OUTPUT -o $INTERNET -p udp \
-s $IPADDR --sport $UNPRIVPORTS \
-d $NAMESEVER --dport 53 \
-j ACCEPT

$IPT -A INPUT -i $INTERNET -p udp \
-s $NAMESEVER --sport 53 \
-d $IPADDR --dport $UNPRIVPORTS \
-j ACCEPT

# DNS retry over TCP
if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	$IPT -A OUTPUT -o $INTERNET -p udp \
	-s $IPADDR --sport $UNPRIVPORTS \
	-d $NAMESEVER --dport 53 \
	-m state --state NEW \
	-j ACCEPT
fi

# static entries as conntrack is not available or not present
$IPT -A OUTPUT -o $INTERNET -p tcp \
-s $IPADDR --sport $UNPRIVPORTS \
-d $NAMESEVER --dort 53 \
-j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp \
-s $NAMESEVER --sport 53 \
-d $IPADDR --dport $UNPRIVPORTS \
-j ACCEPT

# Allowing NDS lookups as a Forwarding server
# Assuming using (s/d)port 53 for server-server exchange

# Email(TCP SMTP Port 25,POP Port 110,IMAP Port 143)
# Relay outgoing email with ISP's relay server
SMTP_GATEWAY="my.isp.server" 			# External mail server or relay

if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	$IPT -A OUTPUT -o $INTERNET -p tcp \
	-s $IPADDR --sport $UNPRIVPORTS \
	-d $SMTP_GATEWAY --dport 25 \
	-m state --state NEW \
	-j ACCEPT
fi

# fallback to stateless firewall rules
$IPT -A OUTPUT -o $INTERNET -p tcp \
-s $IPADDR --sport $UNPRIVPORTS \
-d $SMTP_GATEWAY --dport 25 \
-j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp ! --syn \
-s $SMTP_GATEWAY --sport 25 \
-d $IPADDR --dport $UNPRIVPORTS \
-j ACCEPT


# Sending mail to any external mail server
if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	$IPT -A OUTPUT -o $INTERNET -p tcp \
	-s $IPADDR --sport $UNPRIVPORTS \
	--dport 25 \
	-m state --state NEW \
	-j ACCEPT
fi

# fallback to stateless firewall rules
$IPT -A OUTPUT -o $INTERNET -p tcp \
-s $IPADDR --sport $UNPRIVPORTS \
--dport 25 \
-j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp ! --syn \
-d $IPADDR --dport $UNPRIVPORTS \
--sport 25 \
-j ACCEPT

# Reveiving mail as a local SMTP server
if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	$IPT -A INPUT -i $INTERNET -p tcp \
	--sport $UNPRIVPORTS \
	-d $IPADDR --dport 25 \
	-m state --state NEW ACCEPT
fi

# fallback to stateless 
$IPT -A INPUT -i $INTERNET -p tcp \
--sport $UNPRIVPORTS \
-d $IPADDR --dport 25 -j ACCEPT

$IPT -A OUTPUT -o $INTERNET -p tcp ! --syn \
-s $IPADDR --sport 25 \
--dport $UNPRIVPORTS -j ACCEPT

# Retriving Mail as a POP Client (TCP Port 110 or 995)
POP_SERVER="my.isp.pop.server" 				# External POP server
if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	$IPT -A OUTPUT -p tcp \
	-s $IPADDR --sport $UNPRIVPORTS \
	-d $POP_SERVER --dport 110 \
	-m state --state NEW -j ACCEPT
fi

$IPT -A OUTPUT -o $INTERNET -p tcp \
-s $IPADDR --sport $UNPRIVPORTS \
-d $POP_SERVER --dport 110 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp ! --syn \
-s $POP_SERVER --sport 110 \
-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT

# Receiving Mail as an IMAP Client
IMAP_SERVER="my.isp.imap.server"
if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	$IPT -A OUTPUT -p tcp \
	-s $IPADDR --sport $UNPRIVPORTS \
	-d $IMAP_SERVER --dport 143 \
	-m state --state NEW -j ACCEPT
fi

$IPT -A OUTPUT -o $INTERNET -p tcp \
-s $IPADDR --sport $UNPRIVPORTS \
-d $IMAP_SERVER --dport 143 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp ! --syn \
-s $IMAP_SERVER --sport 143 \
-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT


# Hosting a POP over SSL server for remote clients
# POP_CLIENTS="network/mask"
if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	$IPT -A INPUT -i $INTERNET -p tcp \
	<-s clients> --sport $UNPRIVPORTS \
	-d $IPADDR --dport 995 \
	-m state --state NEW -j ACCEPT
fi

# fallback to stateless
$IPT -A INPUT -i $INTERNET -p tcp \
<-s clients> --sport $UNPRIVPORTS \
-d $IPADDR --dport 995 -j ACCEPT

$IPT -A OUTPUT -o $INTERNET -p tcp ! --syn \
<-d clients> --dport $UNPRIVPORTS \
-s $IPADDR --sport 995 -j ACCEPT

# SSH
SSH_PORTS="1024:65535"				# RSA authentication
#SSH_PORTS="1020:65535"				# RHOST authentication

# allow access to remote SSH server
if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	$IPT -A OUTPUT -o $INTERNET -p tcp \
	-s $IPADDR --sport $SSH_PORTS \
	<-d [remote]> --dport 22 \
	-m state --state NEW -j ACCEPT
fi

# fallback to stateless
$IPT -A OUTPUT -o $INTERNET -p tcp \
-s $IPADDR --sport $SSH_PORTS \
--dport 22 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp ! --syn \
-d $IPADDR --dport $SSH_PORTS \
--sport 22 -j ACCEPT

# allow access to this server
if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	$IPT -A INPUT -i $INTERNET -p tcp \
	--sport $SSH_PORTS \
	-d $IPADDR --dport 22 \
	-m state --state NEW -j ACCEPT
fi

$IPT -A INPUT -i $INTERNET -p tcp \
-d $IPADDR --dport 22 \
--sport $SSH_PORTS -j ACCEPT

$IPT -A OUTPUT -o $INTERNET -p tcp ! --syn \
-s $IPADDR --sport 22 \
--dport $SSH_PORTS -j ACCEPT

# FTP

# allow outgoing FTP control stream
if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	$IPT -A OUTPUT -o $INTERNET -p tcp \
	-s $IPADDR --sport $UNPRIVPORTS \
	--dport 21 \
	-m state --state NEW -j ACCEPT
fi

# fallback to stateless
$IPT -A OUTPUT -o $INTERNET -p tcp \
-s $IPADDR --sport $SSH_PORTS \
--dport 21 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp ! --syn \
-d $IPADDR --dport $UNPRIVPORTS \
--sport 21 -j ACCEPT

# Port-mode FTP data channels
if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	$IPT -A INPUT -i $INTERNET -p tcp \
	--sport 20 \
	-d $IPADDR --dport $UNPRIVPORTS \
	-m state --state NEW -j ACCEPT
fi

$IPT -A INPUT -i $INTERNET -p tcp \
--sport 20 \
-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT

$IPT -A OUTPUT -o $INTERNET -p tcp ! --syn \
-s $IPADDR --sport $UNPRIVPORTS \
--dport 20 -j ACCEPT

# DHCP
# initialization or rebinding :No lease or lease time expired
$IPT -A OUTPUT -o $INTERNET -p udp \
-s $BROADCAST_SRC --sport 67:68 \
-d $BROADCAST_DEST --dport 67:68 -j ACCEPT

# Incoming DHCPOFFER from available DHCP server
$IPT -A INPUT -i $INTERNET -p udp \
--sport 67:68 \
--dport 67:68 -j ACCEPT

# NTP 
TIME_SERVER="my.time.server"

# query as a client
if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	$IPT -A OUTPUT -o $INTERNET -p udp \
	-s $IPADDR --sport $UNPRIVPORTS \
	-d $TIME_SERVER --dport 123 \
	-m state --state NEW -j ACCEPT
fi

$IPT -A OUTPUT -o $INTERNET -p udp \
-s $IPADDR --sport $UNPRIVPORTS \
-d $TIME_SERVER --dport 123 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p udp \
-s $TIME_SERVER --sport 123 \
-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT

# END of MAIN
# log all incoming and dropped packets
$IPT -A INPUT -i $INTERNET -j LOG --log-prefix "Incoming but dropped: "

# log all outgoing and dropped packets
$IPT -A OUTPUT -o $INTERNET -j LOG --log-prefix "Outgoing but Dropped: "






















