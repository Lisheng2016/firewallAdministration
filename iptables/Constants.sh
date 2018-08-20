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