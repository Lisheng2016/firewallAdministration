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
