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

#################################################################
# Rule Specification

# loopback
$NFT add rule filter input iifname lo accept 
$NFT add rule filter output oifname lo accept

# Connection state
# Using conntrack to bypass already established or related traffic
$NFT add rule filter input ct state established,related accept
$NFT add rule filter input ct state invalid log prefix \"INVALID input: \" limit 
rate 3/second drop
$NFT add rule filter output ct state established,related accept
$NFT add rule filter output ct state invalid log prefix \"INVALID output: \" limit 
rate 3/second drop

# refuse source address spoofing
$NFT add rule filter input iifname $INTERNET ip saddr $IPADDR

# There is no need to block outgoing packet's destinating for yourself 
# as it will be sent to lo interface anyway,this is to say,the packet 
# sent from your machine and to your machine never reaches external 
# interface

# invalid address from CLASS_A,CLASS_B and CLASS_C private network and loopback
$NFT add rule filter input iifname $INTERNET ip saddr $CLASS_A drop
$NFT add rule filter input iifname $INTERNET ip saddr $CLASS_B drop
$NFT add rule filter input iifname $INTERNET ip saddr $CLASS_C drop
$NFT add rule filter input iifname $INTERNET ip saddr $LOOPBACK drop

# reject malformed broadcast packages
$NFT add rule filter input iifname $INTERNET ip saddr $BROADCAST_DEST \
 log prefix \"With 255.255.255.255 as source: \" limit rate 3/second drop
$NFT add rule filter input iifname $INTERNET ip saddr $BROADCAST_SRC \
 log prefix \"With 0.0.0.0 as destination: \" limit rate 3/second drop

# Refuse directed broadcasts used to map networks and form DOS attacks
$NFT add rule filter input iifname $INTERNET ip daddr $SUBNET_BASE drop
$NFT add rule filter input iifname $INTERNET ip daddr $SUBNET_BROADCAST drop

# CLASS_D multicast 
# Refuse CLASS_D multicast address Illegal as soure address
$NFT add rule filter input iifname $INTERNET ip saddr $CLASS_D_MULTICAST drop
# Legitimate multicast packets are always UDP packets
# Refuse any not-udp packets to CLASS_D_MULTICAST address
$NFT add rule filter input iifname $INTERNET ip daddr $CLASS_D_MULTICAST ip protocol \
!= udp drop
# Accept incoming multicast packets
$NFT add rule filter input iifname $INTERNET ip daddr $CLASS_D_MULTICAST ip protocol \
udp accept

# CLASS_E address
$NFT add rule filter input iifname $INTERNET ip saddr $CLASS_E_RESERVED_NET drop

# X Window connection establishment
# Refuse initializing from server to other machine
XWINDOW_PORTS="6000-6063"   			# (TCP) X Windows

$NFT add rule filter output oifname $INTERNET ct state new tcp dport $XWINDOWS_PORTS reject
# Refuse all incoming establishment attemps to XWindows as all X traffic should
# be tunnelled through SSH
$NFT add rule filter input iifname $INTERNET ct state new tcp dport $XWINDOWS_PORTS drop

# NFS,Openwindows,squid or socks connection establishment
NFS_PORT="2049"							# (TCP) NFS
SOCKS_PORT="1080"						# (TCP) SOCKS
OPENWINDOWS_PORT="2000"					# (TCP) OpenWindows
SQUID_PORT="3128"						# (TCP) Squid
$NFS add rule filter input iifname $INTERNET tcp dport \
{$SQUID_PORT,$NFS_PORT,$OPENWINDOWS_PORT,$SOCKS_PORT} ct state new drop

$NFS add rule filter output oifname $INTERNET tcp dport \
{$SQUID_PORT,$NFS_PORT,$OPENWINDOWS_PORT,$SOCKS_PORT} ct state new reject

# NFS and RPC lockd
LOCKD_PORT="4045"						# (TCP) RPC LOCKD for NFS
$NFT add rule filter input iifname $INTERNET udp dport \
{$NFS_PORT,$LOCKD_PORT} drop

$NFT add rule filter output oifname $INTERNET udp dport \
{$NFS_PORT,$LOCKD_PORT} reject

# DNS lookup/query
$NFT add rule filter output oifname $INTERNET ip saddr $INTERNET \
udp sport $UNPRIVPORTS ip daddr $NAMESEVER udp dport 53 ct state new accept

$NFT add rule filter input iifname $INTERNET ip saddr $NAMESEVER \
udp sport 53 ip daddr $INTERNET udp dport $UNPRIVPORTS accept

# DNS retries over TCP
$NFT add rule filter output oifname $INTERNET ip daddr $NAMESEVER tcp \
dport 53 ip sddr $IPADDR sport $UNPRIVPORTS ct state new accept

$NFT add rule filter input iifname $INTERNET ip saddr $NAMESEVER tcp \
sport 53 ipaddr $INTERNET dport $UNPRIVPORTS flags != syn accept

# Email(TCP SMTP Port 25,POP/s Port 110/995,IMAP/s Port 143/993)
# Relay outgoing email with ISP's relay server
$NFT add rule filter output oifname $INTERNET ip daddr $SMTP_GATEWAY tcp dport 25 \
ip sddr $IPADDR tcp sport $UNPRIVPORTS accept

$NFT add rule filter input iifname $INTERNET ip saddr $SMTP_GATEWAY tcp sport 25 \
ip daddr $IPADDR tcp dport $UNPRIVPORTS tcp flags != syn accept

# Sending mail to any external mail server
$NFT add rule output oifname $INTERNET ip saddr $IPADDR tcp sport $UNPRIVPORTS 
tcp dport 25 accept

$NFT add rule input iifname $INTERNET ip daddr $IPADDR tcp dport $UNPRIVPORTS 
tcp sport 25 tcp flags != syn accept

# Receving mail as an internal smtp server(TCP Port 25)
$NFT add rule filter input iifname $INTERNET ip daddr $IPADDR tcp dport 25 tcp sport $UNPRIVPORTS 
accept

$NFT add rule filter output oifname $INTERNET ip saddr $IPADDR tcp sport 25 tcp dport $UNPRIVPORTS
tcp flags != syn accept

# Receving mail as an POP over SSL client
$NFT add rule filter input iifname $INTERNET ip daddr $IPADDR tcp dport $UNPRIVPORTS \
ip saddr $POP_SERVER tcp sport 995 tcp flags != syn accept

$NFT add rule filter output oifname $INTERNET ip saddr $IPADDR tcp sport $UNPRIVPORTS \
ip daddr $POP_SERVER dport 995 accept

# Receving mail as an IMAP over SSL client
$NFT add rule filter input iifname $INTERNET ip daddr $IPADDR tcp dport $UNPRIVPORTS \
ip saddr $IMAP_SERVER tcp sport 993 tcp flags != syn accept

$NFT add rule filter output oifname $INTERNET ip saddr $IPADDR tcp sport $UNPRIVPORTS \
ip daddr $IMAP_SERVER dport 993 accept

# Hosting POP over SSL server* for remote clients
# POP_CLIENTS="network/mask"
$NFT add rule filter input iifname $INTERNET ip daddr $IPADDR \
tcp dport 995 tcp sport $UNPRIVPORTS accept

$NFT add rule filter output oifname $INTERNET ip saddr $IPADDR \
tcp sport 995 tcp dport $UNPRIVPORTS tcp flags != syn accept 

# SSH
SSH_PORTS="1024-65535"				# RSA authentication
#SSH_PORTS="1020-65535"				# RHOST authentication

# allow access to remote SSH server
$NFT add rule filter output oifname $INTERNET ip saddr $IPADDR tcp sport $SSH_PORTS 
tcp dport 22 accept

$NFT add rule filter input iifname $INTERNET ip daddr $IPADDR tcp dport $SSH_PORTS 
tcp sport 22 tcp flags != syn accept

# allowing SSH access to this server
$NFT add rule filter input iifname $INTERNET ip daddr $IPADDR tcp dport 22  
tcp sport $SSH_PORTS accept

$NFT add rule filter output oifname $INTERNET ip saddr $IPADDR tcp sport 22 
tcp dport $SSH_PORTS tcp flags != syn accept

# allowing outgoing FTP control channel
$NFT add rule filter output oifname $INTERNET ip saddr $IPADDR tcp sport $UNPRIVPORTS 
tcp dport 21 accept

$NFT add rule filter input iifname $INTERNET ip daddr $IPADDR tcp dport $UNPRIVPORTS 
tcp sport 21 accept

# FTP client mode (notice : not FTP server mode!)
# Assume using ct state model for ftp
# outgoing FTP control channel packets as a client
$NFT add rule filter output oifname $INTERNET ip saddr $IPADDR tcp sport $UNPRIVPORTS 
tcp dport 21 tcp flags != syn accept
# incoming FTP control channel packets from server
$NFT add rule filter input iifname $INTERNET ip daddr $IPADDR tcp dport $UNPRIVPORTS 
tcp sport 21 accept

# DHCP
# initialization or rebinding :No lease or lease time expired
$NFT add rule filter output oifname $INTERNET ip saddr $BROADCAST_SRC udp sport 67-68 ip daddr $BROADCAST_DEST
udp dport 67-68  accept

# Incoming DHCPOFFER from available DHCP server
$NFT add rule filter input iifname $INTERNET udp sport 67-68 udp dport 67-68 accept

# DHCP
# DHCPDISCOVER from this machine
$NFT add rule filter output oifname $INTERNET ip saddr $BROADCAST_SRC udp sport 68 \
ip daddr $BROADCAST_DEST udp dport 67 accept
# DHCPOFFER from potential server
$NFT add rule filter input iifname $INTERNET ip saddr $BROADCAST_SRC udp sport 67 \
ipdaddr $BROADCAST_DEST udp dport 68 accept
# DHCP address renew and client is aware of the exising server 
# DHCPREQUEST
$NFT add rule filter output oifname $INTERNET ip saddr $BROADCAST_SRC udp sport 68 \
daddr $BROADCAST_DEST udp dport 67 accept
# DHCPACK
$NFT add rule filter input iifname $INTERNET ip saddr $DHCP_SERVER udp sport 67 \
ip daddr $IPADDR udp dport 68 accept

# NTP 
# query as a client
$NFT add rule filter output oifname $INTERNET udp ip saddr $IPADDR udp sport $UNPRIVPORTS 
ip daddr $TIME_SERVER udp dport 123 accept

$NFT add rule filter input iifname $INTERNET udp ip daddr $IPADDR udp dport $UNPRIVPORTS 
ip saddr $TIME_SERVER udp sport 123 accept

# log all incoming and dropped packets
$NFT add rule filter input iifname $INTERNET log prefix \"Incoming but dropped: \" limit rate 3/second
# log all outgoing and dropped packets
$NFT add rule filter output oifname $INTERNET log prefix \"Outgoing but dropped: \" limit rate 3/second

# default policies
$NFT add rule filter input iifname $INTERNET drop
$NFT add rule filter output oifname $INTERNET reject
                













