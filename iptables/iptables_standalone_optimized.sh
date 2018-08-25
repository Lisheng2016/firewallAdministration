#! /bin/sh

# Enable ftp data channel connection-tracking
MODPROBE=`which modprobe`
$MODPROBE ip_conntrack_ftp

# Defining isConntrack variable
isConntrack=`lsmod | grep ^nf_conntrack_ipv4 | awk '{print $1}'`
if [ ${isConntrack} = "nf_conntrack_ipv4" ];then
	CONNECTION_TRACKING=1
else
 	CONNECTION_TRACKING=0
fi

ACCEPT_AUTH="0"
SSH_SERVER="1"
FTP_SERVER="1"
WEB_SERVER="0"
SSL_SERVER="0"
DHCP_CLIENT="0"
POP_SERVER="0"
POP_CLIENT="1"
IMAP_CLIENT="1"

# Location of iptables on your system
IPT=`which iptables`

# Common definitions
INTERNET="eth0"							# Internet-connected interface
LOOPBACK_INTERFACE="lo"					# Loopback interface name
IPADDR="my.ip.address"					# IP address of the internet-connnected interface
MY_ISP="my.isp.address.range"			# ISP server & NOC address range
SUBNET_BASE="my.subnet.network"			# Your subnet's network address
SUBNET_BROADCAST="my.subnet.bcast"		# Your subnet's broadcast address

# External server address
NAMESEVER="my.name.server"				# (TCP/UDP) DNS
POP_SERVER="my.isp.pop.server" 			# External POP server
MAIL_SERVER="my.isp.mail.server"		# External mail server
JENKINS_SERVER="my.jenkins.server"		# External Jenkins server
TIME_SERVER="my.time.server"			# External time server
DHCP_SERVER="my.isp.dhcp.server"		# ISP's DHCP server
IMAP_SERVER="my.imap.server"			# External IMAP Server
TRUSTED_HOSTS="my.hosts"				# Trusted icmp request hosts

# Common network ranges
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
SSH_PORTS="1024:65535"					# RSA authentication
#SSH_PORTS="1020:65535"					# RHOST authentication

#################################################################
# Enable broadcast echo protection 
# ignore an echo request to a broadcast address thus preventing compromising all host 
# at one time
echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
b
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
# Removing all existing rules from all chains
$IPT --flush

# use -t to specify tables to flush
$IPT -t nat -F 
$IPT -t mangle -F 

# Deleting all user-defined chains
for tables in filter nat mangle
do 
	$IPT -t ${tables} -X
done

# Resetting Default Policies 
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

# Unlimit traffic on the loopback interface
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# Set the default policy to Drop
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

#################################################################
# Stealth Scans and TCP State Flags
# All of the bits are cleared
$IPT -A INPUT -p tcp --tcp-flags ALL none -j DROP

# SYN and FIN are both Set
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# SYN and RST are both Set
$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# FIN and RST are both Set
$IPT -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP

# FIN is the only bit set ,but not with the expected accompanying ACK set
$IPT -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP

# PSH is the only bit set ,but not with the expected accompanying ACK set
$IPT -A INPUT -p tcp --tcp-flags PSH,ACK PSH -j DROP

# URG is the only bit set ,but not with the expected accompanying ACK set
$IPT -A INPUT -p tcp --tcp-flags URG,ACK URG -j DROP

#################################################################
# Using Conntrack to bypass rule checking
if [ $CONNECTION_TRACKING = "1" ];then
	$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	$IPT -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

	$IPT -A INPUT -m state --state INVALID -j LOG \
			--log-prefix "INVALID input: "
	$IPT -A INPUT -m state --state INVALID -j DROP

	$IPT -A OUTPUT -m state --state INVALID -j LOG \
			--log-prefix "INVALID output: "
	$IPT -A OUTPUT -m state --state INVALID -j DROP
fi

#################################################################
# Source Address Spoofing and Other Bad Address
# Refuse spoofed packets pretending to be from IPADDR of server's 
# ethernet adaptor
$IPT -A INPUT -i $INTERNET -s $IPADDR -j DROP

# There is no need to block outgoing packet's destined for yourself 
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

if "$DHCP_CLIENT" = "0" ];then
	# Refuse directed broadcasts used to map networks and form
	# DOS attacks
	$IPT -A INPUT -i $INTERNET -d $SUBNET_BASE -j DROP
	$IPT -A INPUT -i $INTERNET -d $SUBNET_BROADCAST -j DROP

	# Refuse limited broadcasts
	$IPT -A INPUT -i $INTERNET -d $BROADCAST_DEST -j DROP
fi

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

if [ $DHCP_CLIENT = "1" ];then
	# following rules matches DHCP offering
	$IPT -A INPUT -i $INTERNET -p udp \
		-s $BROADCAST_SRC --sport 67 \
		-d $BROADCAST_DEST --dport 68 -j ACCEPT
fi
# refuse address defined as reserved by the IANA
# 0.*.*.*      					-Can not be block due to DHCP 
# 169.254.0.0/16 				- Link local networks
# 192.0.2.0/24					-TEST-NET

$IPT -A INPUT -i $INTERNET -s 0.0.0.0/8 -j DROP
$IPT -A INPUT -i $INTERNET -s 169.254.0.0/16 -j DROP
$IPT -A INPUT -i $INTERNET -s 192.0.2.0/24 -j DROP

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


#################################################################
# DNS Name Server

# DNS Forwarding Name Server or client requests
if [ ${CONNECTION_TRACKING} = "1" ];then
	$IPT -A OUTPUT -o $INTERNET -p udp \
		-s $IPADDR --sport $UNPRIVPORTS \
		-d $NAMESEVER --dport 53 \
		-m state --state NEW -j ACCEPT
fi

# fallback to static rules
$IPT -A OUTPUT -o $INTERNET -p udp \
	-s $IPADDR --sport $UNPRIVPORTS \
	-d $NAMESEVER --dport 53 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p udp \
	-s $NAMESEVER --sport 53 \
	-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT

#................................................................
# TCP is used for larger responses

if [ ${CONNECTION_TRACKING} = "1" ];then
	$IPT -A OUTPUT -o $INTERNET -p udp \
		-s $IPADDR --sport $UNPRIVPORTS \
		-d $NAMESEVER --dport 53 \
		-m state --state NEW -j ACCEPT
fi

# static entries as conntrack is not available or not present
$IPT -A OUTPUT -o $INTERNET -p tcp \
	-s $IPADDR --sport $UNPRIVPORTS \
	-d $NAMESEVER --dport 53 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp \
	-s $NAMESEVER --sport 53 \
	-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT

#................................................................
# DNS Caching Name Server (local server to primary server)
# Assuming using (s/d)port 53 for server-server exchange
# client 53 <=====> server 53
if [ ${CONNECTION_TRACKING} = "1" ];then
	$IPT -A OUTPUT -o $INTERNET -p udp \
		-s $IPADDR --sport 53 \
		-d $NAMESEVER --dport 53 \
		-m state --state NEW -j ACCEPT
fi

# static entries as conntrack is not available or not present
$IPT -A OUTPUT -o $INTERNET -p tcp \
	-s $IPADDR --sport 53 \
	-d $NAMESEVER --dport 53 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp \
	-s $NAMESEVER --sport 53 \
	-d $IPADDR --dport 53 -j ACCEPT

#................................................................
# Incoming Remote Client Requests to local Servers
if [ $ACCEPT_AUTH = "1" ];then
	if [ ${CONNECTION_TRACKING} = "1" ];then
		$IPT -A OUTPUT -o $INTERNET -p udp \
			-s $IPADDR --sport $UNPRIVPORTS \
			-d $NAMESEVER --dport 113 \
			-m state --state NEW -j ACCEPT
	fi
# static entries as conntrack is not available or not present
	$IPT -A OUTPUT -o $INTERNET -p tcp \
		-s $IPADDR --sport $UNPRIVPORTS \
		-d $NAMESEVER --dport 53 -j ACCEPT

	$IPT -A INPUT -i $INTERNET -p tcp \
		-s $NAMESEVER --sport 113 \
		-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT
else
	$IPT -A INPUT -i $INTERNET -p tcp \
		--sport $UNPRIVPORTS \
		-d $IPADDR --dport 113 -j REJECT --reject-with tcp-reset
fi

#################################################################
# Sening Email to External Email Server (TCP SMTP Port 25,POP Port 110,IMAP Port 143)
# Use <-d $SMTP_RELAY> if you are using ISP's relaying service
if [ ${CONNECTION_TRACKING} = "1" ];then
	$IPT -A OUTPUT -o $INTERNET -p tcp \
		-s $IPADDR --sport $UNPRIVPORTS \
		--dport 25 -m state --state NEW -j ACCEPT
fi

# fallback to stateless firewall rules
$IPT -A OUTPUT -o $INTERNET -p tcp \
	-s $IPADDR --sport $UNPRIVPORTS \
	--dport 25 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp ! --syn \
--sport 25 \
-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT

#################################################################
# Reveiving mail as a local SMTP server
if [ $SMTP_SERVER = "1" ];then
	if [ ${CONNECTION_TRACKING} = "1" ];then
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
fi

#################################################################
# Retriving Mail as a POP Client (TCP Port 110 or 995)
if [ $POP_CLIENT = "1" ];then
	if [ ${CONNECTION_TRACKING} = "1" ];then
		$IPT -A OUTPUT -p tcp \
			-s $IPADDR --sport $UNPRIVPORTS \
			-d $POP_SERVER --dport 995 \
			-m state --state NEW -j ACCEPT
	fi

	$IPT -A OUTPUT -o $INTERNET -p tcp \
		-s $IPADDR --sport $UNPRIVPORTS \
		-d $POP_SERVER --dport 995 -j ACCEPT

	$IPT -A INPUT -i $INTERNET -p tcp ! --syn \
		-s $POP_SERVER --sport 995 \
		-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT
fi

#################################################################
# Receiving Mail as an IMAP Client
if [ $IMAP_CLIENT = "1" ];then
	if [ ${CONNECTION_TRACKING} = "1" ];then
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
fi

#################################################################
# Hosting a POP over SSL server for remote clients
# POP_CLIENTS="network/mask"
if [ $POP_SERVER = "1" ];then
	if [ ${CONNECTION_TRACKING} = "1" ];then
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
fi

#################################################################
# SSH (TCP Port 22)
# as ssh client
if [ ${CONNECTION_TRACKING} = "1" ];then
	$IPT -A OUTPUT -o $INTERNET -p tcp \
		-s $IPADDR --sport $SSH_PORTS \
		--dport 22 \
		-m state --state NEW -j ACCEPT
fi

# fallback to stateless
$IPT -A OUTPUT -o $INTERNET -p tcp \
	-s $IPADDR --sport $SSH_PORTS \
	--dport 22 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp ! --syn \
	-d $IPADDR --dport $SSH_PORTS \
	--sport 22 -j ACCEPT



#................................................................
# as ssh server
if [ $SSH_SERVER = "1" ];then
	if [ ${CONNECTION_TRACKING} = "1" ];then
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
fi

#################################################################
# FTP (TCP Port 21,20 or unprivileged ports)
# allow outgoing FTP control stream
if [ ${CONNECTION_TRACKING} = "1" ];then
	$IPT -A OUTPUT -o $INTERNET -p tcp \
		-s $IPADDR --sport $UNPRIVPORTS \
		--dport 21 -m state --state NEW -j ACCEPT
fi

# fallback to stateless
$IPT -A OUTPUT -o $INTERNET -p tcp \
	-s $IPADDR --sport $SSH_PORTS \
	--dport 21 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp ! --syn \
	-d $IPADDR --dport $UNPRIVPORTS \
	--sport 21 -j ACCEPT

# Port-mode FTP data channels
if [ ${CONNECTION_TRACKING} = "1" ];then
	# This rule is not neccessary if ip_conntrack_ftp module is used
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

# Passive-mode FTP data channels
if [ ${CONNECTION_TRACKING} = "1" ];then
	# if ip_conntrack_ftp is used this rule is not neccessary
	$IPT -A INPUT -i $INTERNET -p tcp \
		--sport $UNPRIVPORTS \
		-d $IPADDR --dport $UNPRIVPORTS \
		-m state --state NEW -j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp \
	--sport $UNPRIVPORTS \
	-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT

$IPT -A OUTPUT -o $INTERNET -p tcp ! --syn \
	-s $IPADDR --sport $UNPRIVPORTS \
	--dport $UNPRIVPORTS -j ACCEPT

#................................................................
# Incoming Remote Client Requests to Local Servers
if [ $FTP_SERVER = "1" ];then
	if [ $CONNECTION_TRACKING = "1" ];then
		$IPT -A INPUT -i $INTERNET -p tcp \
			--sport $UNPRIVPORTS
			-d $IPADDR --dport 21 \
			-m state --state NEW -j ACCEPT
	fi

	$IPT -A INPUT -i $INTERNET -p tcp \
		--sport $UNPRIVPORTS \
		-d $IPADDR --dport 21 -j ACCEPT

	$IPT -A OUTPUT -o $INTERNET -p tcp ! --syn \
		-s $IPADDR --sport 21 \
		--dport $UNPRIVPORTS -j ACCEPT

	# Outgoing Port-mode Data Channel connection to Port 20
	if [ $CONNECTION_TRACKING = "1" ];then
		$IPT -A OUTPUT -p tcp \
		-s $IPADDR --sport 20 \
		--dport $UNPRIVPORTS -m state --state NEW -j ACCEPT
	fi

	$IPT -A OUTPUT -o $INTERNET -p tcp ! --syn \
		-s $IPADDR --sport 20 \
		--dport $UNPRIVPORTS -j ACCEPT

	$IPT -A INPUT -i $INTERNET -p tcp \
		--sport $UNPRIVPORTS \
		-d $IPADDR --dport 20 -j ACCEPT

	# Incoming Passive Mode Data Channel connection to unprivileged ports
	if [ $CONNECTION_TRACKING = "1" ];then
		$IPT -A INPUT -p tcp \
		-d $IPADDR --dport $UNPRIVPORTS \
		--sport $UNPRIVPORTS -m state --state NEW -j ACCEPT
	fi

	$IPT -A INPUT -i $INTERNET -p tcp \
		--sport $UNPRIVPORTS \
		-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT

	$IPT -A OUTPUT -o $INTERNET -p tcp ! --syn \
		-s $IPADDR --sport $UNPRIVPORTS \
		--dport $UNPRIVPORTS -j ACCEPT
fi

#################################################################
# HTTP Web Traffic (TCP Port 80)

# Outgoing Local client requests to remote server
if [ ${CONNECTION_TRACKING} = "1" ];then
	$IPT -A OUTPUT -i $INTERNET -p tcp \
		-s $IPADDR --sport $UNPRIVPORTS \
		--dport 80 -m state --state NEW -j ACCEPT

$IPT -A OUTPUT -o $INTERNET -p tcp \
	-s $IPADDR --sport $UNPRIVPORTS \
	--dport 80 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp ! --syn \
	--sport 80 \
	-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT

#................................................................
# Incoming Remote Client Requests to Local Servers
if [ $WEB_SERVER = "1" ];then
	if [ $CONNECTION_TRACKING = "1" ];then
		$IPT -A INPUT -p tcp \
		-d $IPADDR --dport 80 \
		--sport $UNPRIVPORTS -m state --state NEW -j ACCEPT
	fi

	$IPT -A INPUT -i $INTERNET -p tcp \
		--sport $UNPRIVPORTS \
		-d $IPADDR --dport 80 -j ACCEPT

	$IPT -A OUTPUT -o $INTERNET -p tcp ! --syn \
		-s $IPADDR --sport 80 \
		--dport $UNPRIVPORTS -j ACCEPT
fi

#################################################################
# SSL Web Traffic (TCP Port 443)

# Outgoing local client requests to remote server
if [ ${CONNECTION_TRACKING} = "1" ];then
	$IPT -A OUTPUT -i $INTERNET -p tcp \
		-s $IPADDR --sport $UNPRIVPORTS \
		--dport 443 -m state --state NEW -j ACCEPT

$IPT -A OUTPUT -o $INTERNET -p tcp \
	-s $IPADDR --sport $UNPRIVPORTS \
	--dport 443 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp ! --syn \
	--sport 443 \
	-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT

#................................................................
# Incoming Remote Client Requests to Local Servers
if [ $WEB_SERVER = "1" ];then
	if [ $CONNECTION_TRACKING = "1" ];then
		$IPT -A INPUT -p tcp \
		-d $IPADDR --dport 443 \
		--sport $UNPRIVPORTS -m state --state NEW -j ACCEPT
	fi

	$IPT -A INPUT -i $INTERNET -p tcp \
		--sport $UNPRIVPORTS \
		-d $IPADDR --dport 443 -j ACCEPT

	$IPT -A OUTPUT -o $INTERNET -p tcp ! --syn \
		-s $IPADDR --sport 443 \
		--dport $UNPRIVPORTS -j ACCEPT
fi

#################################################################
# whois (TCP Port 43)

# Outgoing local client requests to remote server
if [ ${CONNECTION_TRACKING} = "1" ];then
	$IPT -A OUTPUT -i $INTERNET -p tcp \
		-s $IPADDR --sport $UNPRIVPORTS \
		--dport 43 -m state --state NEW -j ACCEPT

$IPT -A OUTPUT -o $INTERNET -p tcp \
	-s $IPADDR --sport $UNPRIVPORTS \
	--dport 43 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p tcp ! --syn \
	--sport 43 \
	-d $IPADDR --dport $UNPRIVPORTS -j ACCEPT

#################################################################
# Accessing Remote Network Time Servers (UDP Port 123)
# query as a client and with source port fixed on port 123
if [ ${CONNECTION_TRACKING} = "1" ];then
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


#################################################################
# Accessing ISP's DHCP Server (UDP Port 67-68)

# Some broadcast packets are explicitly ignored by the firewall
# Others are dropped by the default policy
# DHCP tests must precede broadcast-related rules ,as DHCP relies 
# on broadcast traffic initially

if [ $DHCP_CLIENT = "1" ];then
	# Initialization or rebinding :No lease or lease time expired
	$IPT -A OUTPUT -o $INTERNET -p udp \
		-s $BROADCAST_SRC --sport 68 \
		-d $BROADCAST_DEST --dport 67 -j ACCEPT

	# Incoming DHCPOFFER from available DHCP servers
	$IPT -A INPUT -i $INTERNET -p udp \
		-s $BROADCAST_SRC --sport 67 \
		-d $BROADCAST_DEST --dport 68 -j ACCEPT

	# Fall back to Initialization
	# The client knows its server, to perform a renew or confirm after reboot
	$IPT -A OUTPUT -o $INTERNET -p udp \
		-s $BROADCAST_SRC --sport 68 \
		-d $DHCP_SERVER --dport 67 -j ACCEPT

	# Incoming DHCPOFFER as a unicast to our server
	$IPT -A INPUT -i $INTERNET -p udp \
		-s $DHCP_SERVER --sport 67 \
		-d $BROADCAST_DEST --dport 68 -j ACCEPT

	# As a result of the above ,we're supposed to change our ip address
	# with this message <-s $DHCP -d 255.255.255.255> 
	# Depending on the server implementation,the destination address 
	# can be the new address,subnet address, or the limited broadcast address

	# If the network subnet address is used as the destination,
	# the next rule must allow incoming packets detined to the subnet address,
	# and the rule must precede any general rules that block such incoming
	# broadcast packets

# Incoming DHCPOFFER from available DHCP server
$IPT -A INPUT -i $INTERNET -p udp \
	-s $DHCP_SERVER --sport 67 \
	--dport 68 -j ACCEPT

$IPT -A OUTPUT -o $INTERNET -p udp \
	-s $IPADDR --sport 68 \
	-d $IPADDR --dport 67 -j ACCEPT

$IPT -A INPUT -i $INTERNET -p udp \
	-s $DHCP_SERVER --sport 67 \
	-d $IPADDR --dport 68 -j ACCEPT

# Refuse directed broadcasts
# mapping networks and form DOS attacks
$IPT -A INPUT -i $INTERNET -d $SUBNET_BASE -j DROP
$IPT -A INPUT -i $INTERNET -d $SUBNET_BROADCAST -j DROP

# Refuse limited broadcasts
$IPT -A INPUT -i $INTERNET -d $BROADCAST_DEST -j DROP

#################################################################
# ICMP Control and Status messages

# Log and drop initial ICMP fragments
$IPT -A INPUT -i $INTERNET --fragment -p icmp -j LOG \
		--log-prefix "Fragmented ICMP: "
$IPT -A INPUT -i $INTERNET --fragment -p icmp -j DROP

$IPT -A INPUT -i $INTERNET -p icmp \
		--icmp-type source-quench -d $IPADDR -j ACCEPT

$IPT -A OUTPUT -o $INTERNET -p icmp \
		--icmp-type source-quench -s $IPADDR -j ACCEPT

$IPT -A INPUT -i $INTERNET -p icmp \
		--icmp-type parameter-problem -d $IPADDR -j ACCEPT

$IPT -A OUTPUT -o $INTERNET -p icmp \
		--icmp-type parameter-problem -s $IPADDR -j ACCEPT

$IPT -A INPUT -i $INTERNET -p icmp \
		--icmp-type destination-unreachable -d $IPADDR -j ACCEPT

$IPT -A OUTPUT -o $INTERNET -p icmp \
		--icmp-type fragmentation-needed -s $IPADDR -j ACCEPT

# Do not log dropped outgoing icmp packets
$IPT -A OUTPUT -o $INTERNET -p icmp \
	-s $IPADDR icmp-type destination-unreachable -j DROP

# Allowing outgoing ping to go to anywhere
if [ $CONNECTION_TRACKING = "1" ];then
	$IPT -A OUTPUT -o $INTERNET -p icmp \
		--icmp-type echo-request -s $IPADDR \
		-m state --state NEW -j ACCEPT
fi

$IPT -A OUTPUT -o $INTERNET -p icmp \
		--icmp-type echo-request -s $IPADDR -j ACCEPT

$IPT -A INPUT -i $INTERNET -p icmp \
		--icmp-type echo-reply -d $IPADDR -j ACCEPT

# Allow incoming pings from trusted hosts
if [ $CONNECTION_TRACKING = "1" ];then 
	$IPT -A INPUT -i $INTERNET -p icmp \
		-s $TRUSTED_HOSTS --icmp-type echo-request \
		-d $IPADDR -m state --state NEW -j ACCEPT
fi

$IPT -A INPUT -i $INTERNET -p icmp \
	-s $TRUSTED_HOSTS -d $IPADDR --icmp-type echo-request -j ACCEPT

$IPT -A OUTPUT -o $INTERNET -p icmp \
	-s $IPADDR -d $TRUSTED_HOSTS --icmp-type echo-reply -j ACCEPT

#################################################################	
# log all incoming and dropped packets
$IPT -A INPUT -i $INTERNET -p tcp -j LOG --log-prefix "Incoming but dropped: "

# log all outgoing and dropped packets
$IPT -A OUTPUT -o $INTERNET -p tcp -j LOG --log-prefix "Outgoing but Dropped: "

