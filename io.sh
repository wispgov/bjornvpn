#!/bin/bash

# BjornVPN AutoScript OpenVPN Server Installer for Debian, Ubuntu, CentOS, Fedora and Arch Linux.
# Modified for Bjorn VPN - with OpenVPN and Squid Proxy Installer from the Angristan AutoScript.
# Contact Number for Donations (09225205353) with GCash Account / Email: binarykorra@icloud.com

function isRoot () {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable () {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS () {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ "$ID" == "debian" ]]; then
			if [[ ! $VERSION_ID =~ (8|9|10) ]]; then
				echo "⚠️ Your version of Debian is not supported."
				echo ""
				echo "However, if you're using Debian >= 9 or unstable/testing then you can continue."
				echo "Keep in mind they are not supported, though."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ "$CONTINUE" = "n" ]]; then
					exit 1
				fi
			fi
		elif [[ "$ID" == "ubuntu" ]];then
			OS="ubuntu"
			if [[ ! $VERSION_ID =~ (16.04|18.04|19.04) ]]; then
				echo "⚠️ Your version of Ubuntu is not supported."
				echo ""
				echo "However, if you're using Ubuntu > 17 or beta, then you can continue."
				echo "Keep in mind they are not supported, though."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ "$CONTINUE" = "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/fedora-release ]]; then
		OS=fedora
	elif [[ -e /etc/centos-release ]]; then
		if ! grep -qs "^CentOS Linux release 7" /etc/centos-release; then
			echo "Your version of CentOS is not supported."
			echo "The script only support CentOS 7."
			echo ""
			unset CONTINUE
			until [[ $CONTINUE =~ (y|n) ]]; do
				read -rp "Continue anyway? [y/n]: " -e CONTINUE
			done
			if [[ "$CONTINUE" = "n" ]]; then
				echo "Ok, bye!"
				exit 1
			fi
		fi
		OS=centos
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS or Arch Linux system"
		exit 1
	fi
}

function initialCheck () {
	if ! isRoot; then
		echo "Sorry, you need to run this as root"
		exit 1
	fi
	if ! tunAvailable; then
		echo "TUN is not available"
		exit 1
	fi
	checkOS
}

function installUnbound () {
	if [[ ! -e /etc/unbound/unbound.conf ]]; then

		if [[ "$OS" =~ (debian|ubuntu) ]]; then
			apt-get install -y unbound

			# Configuration
			echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >> /etc/unbound/unbound.conf

		elif [[ "$OS" = "centos" ]]; then
			yum install -y unbound

			# Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ "$OS" = "fedora" ]]; then
			dnf install -y unbound

			# Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|# use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ "$OS" = "arch" ]]; then
			pacman -Syu --noconfirm unbound

			# Get root servers list
			curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache

			mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old

			echo 'server:
	use-syslog: yes
	do-daemonize: no
	username: "unbound"
	directory: "/etc/unbound"
	trust-anchor-file: trusted-key.key
	root-hints: root.hints
	interface: 10.8.0.1
	access-control: 10.8.0.1/24 allow
	port: 53
	num-threads: 2
	use-caps-for-id: yes
	harden-glue: yes
	hide-identity: yes
	hide-version: yes
	qname-minimisation: yes
	prefetch: yes' > /etc/unbound/unbound.conf
		fi

		if [[ ! "$OS" =~ (fedora|centos) ]];then
			# DNS Rebinding fix
			echo "private-address: 10.0.0.0/8
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96" >> /etc/unbound/unbound.conf
		fi
	else # Unbound is already installed
		echo 'include: /etc/unbound/openvpn.conf' >> /etc/unbound/unbound.conf

		# Add Unbound 'server' for the OpenVPN subnet
		echo 'server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.0.0/8
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96' > /etc/unbound/openvpn.conf
	fi

		systemctl enable unbound
		systemctl restart unbound
}

function defaultAccount () {
	clear
	defCLIENT="trial"
	cd /etc/openvpn/easy-rsa/ || return
	./easyrsa build-client-full "$defCLIENT" nopass
	clear
	
	if [ -e "/var/www/html" ]; then
		homeDir="/var/www/html"
	elif [ "${SUDO_USER}" ]; then
		homeDir="/var/www/html"
	else
		homeDir="/var/www/html"
	fi

	if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
		TLS_SIG="1"
		clear
	elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
		TLS_SIG="2"
		clear
	fi

	cp /etc/openvpn/client-template.md "$homeDir/$defCLIENT.ovpn"
	{
		echo ""
		echo "http-proxy $IP ${squidPORTS[$SquidGEN]}
http-proxy-option CUSTOM-HEADER 'GET https://www.smart.com.ph HTTP/1.0'
http-proxy-option CUSTOM-HEADER 'Host: www.smart.com.ph'
http-proxy-option CUSTOM-HEADER 'Proxy-Connection: Keep-Alive'
http-proxy-option CUSTOM-HEADER 'Connection: Keep-Alive'"
		echo "dhcp-option DNS 23.253.163.53"
		echo "dhcp-option DNS 198.101.242.72"
		echo ""
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"
		echo "<cert>"
		awk '/BEGIN/,/END/' "/etc/openvpn/easy-rsa/pki/issued/$defCLIENT.crt"
		echo "</cert>"
		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$defCLIENT.key"
		echo "</key>"

		case $TLS_SIG in
			1)
				echo "<tls-crypt>"
				cat "/etc/openvpn/tls-crypt.key"
				echo "</tls-crypt>"
			;;
			2)
				echo "key-direction 1"
				echo "<tls-auth>"
				cat "/etc/openvpn/tls-auth.key"
				echo "</tls-auth>"
			;;
		esac
	} >> "$homeDir/$defCLIENT.ovpn"
	setupBanner
}

function installQuestions () {
	echo "Welcome to the BjornVPN - OpenVPN installer!"
	echo ""

	echo "I need to ask you a few questions before starting the setup."
	echo "You can leave the default options and just press enter if you are ok with them."
	echo ""
	echo "I need to know the IPv4 address of the network interface you want OpenVPN listening to."
	echo "Unless your server is behind NAT, it should be your public IPv4 address."

	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "Public IP Address: " -e -i "$IP" IP
	fi
	
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "It seems this server is behind NAT. What is its public IPv4 address or hostname?"
		echo "We need it for the clients to connect to the server."
		until [[ "$ENDPOINT" != "" ]]; do
			read -rp "Public IPv4 address or hostname: " -e ENDPOINT
		done
	fi

	echo ""
	echo "Checking for IPv6 connectivity..."
	echo ""
	# "ping6" and "ping -6" availability varies depending on the distribution
	if type ping6 > /dev/null 2>&1; then
		PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
	fi
	if eval "$PING6"; then
		echo "Your host appears to have IPv6 connectivity."
		SUGGESTION="y"
	else
		echo "Your host does not appear to have IPv6 connectivity."
		SUGGESTION="n"
	fi
	echo ""
	# Ask the user if they want to enable IPv6 regardless its availability.
	until [[ $IPV6_SUPPORT =~ (y|n) ]]; do
		read -rp "Do you want to enable IPv6 support (NAT)? [y/n]: " -e -i $SUGGESTION IPV6_SUPPORT
	done
	echo ""
	echo "What port do you want OpenVPN to listen to?"
	echo "   1) Default: 465"
	echo "   2) Custom"
	echo "   3) Random [49152-65535]"
	until [[ "$PORT_CHOICE" =~ ^[1-3]$ ]]; do
		read -rp "Port choice [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
		1)
			PORT="465"
		;;
		2)
			until [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
				read -rp "Custom port [1-65535]: " -e -i 465 PORT
			done
		;;
		3)
			# Generate random number within private ports range
			PORT=$(shuf -i49152-65535 -n1)
			echo "Random Port: $PORT"
		;;
	esac
	echo ""
	echo "What protocol do you want OpenVPN to use?"
	echo "UDP is faster. Unless it is not available, you shouldn't use TCP."
	echo "   1) TCP"
	echo "   2) UDP"
	until [[ "$PROTOCOL_CHOICE" =~ ^[1-2]$ ]]; do
		read -rp "Protocol [1-2]: " -e -i 1 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
		1)
			PROTOCOL="tcp"
		;;
		2)
			PROTOCOL="udp"
		;;
	esac
	echo ""
	echo "What DNS resolvers do you want to use with BjornVPN?"
	echo "   1) Current system resolvers (from /etc/resolv.conf)"
	echo "   2) Self-hosted DNS Resolver (Unbound)"
	echo "   3) Cloudflare (Anycast: worldwide)"
	echo "   4) Quad9 (Anycast: worldwide)"
	echo "   5) Quad9 uncensored (Anycast: worldwide)"
	echo "   6) FDN (France)"
	echo "   7) DNS.WATCH (Germany)"
	echo "   8) OpenDNS (Anycast: worldwide)"
	echo "   9) Google (Anycast: worldwide)"
	echo "   10) Yandex Basic (Russia)"
	echo "   11) AdGuard DNS (Russia)"
	echo "   12) Philippine DNS (SEA)"
	until [[ "$DNS" =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 12 ]; do
		read -rp "DNS [2 - 12]: " -e -i 12 DNS
			if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
				echo ""
				echo "Unbound is already installed."
				echo "You can allow the script to configure it in order to use it from your OpenVPN clients"
				echo "We will simply add a second server to /etc/unbound/unbound.conf for the OpenVPN subnet."
				echo "No changes are made to the current configuration."
				echo ""

				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Apply configuration changes to Unbound? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE = "n" ]];then
					# Break the loop and cleanup
					unset DNS
					unset CONTINUE
				fi
			fi
	done
	echo ""
	echo "Do you want to use compression? It is not recommended since the VORACLE attack make use of it."
	until [[ $COMPRESSION_ENABLED =~ (y|n) ]]; do
		read -rp"Enable Compression? [y/n]: " -e -i y COMPRESSION_ENABLED
	done
	if [[ $COMPRESSION_ENABLED == "y" ]];then
		echo "Choose which compression algorithm you want to use: (they are ordered by efficiency)"
		echo "   1) LZ4-v2"
		echo "   2) LZ4"
		echo "   3) LZ0"
		until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
			read -rp"Compression algorithm [1-3]: " -e -i 1 COMPRESSION_CHOICE
		done
		case $COMPRESSION_CHOICE in
			1)
			COMPRESSION_ALG="lz4-v2"
			;;
			2)
			COMPRESSION_ALG="lz4"
			;;
			3)
			COMPRESSION_ALG="lzo"
			;;
		esac
	fi
	echo ""
	echo "Do you want to customize encryption settings?"
	echo "Unless you know what you're doing, you should stick with the default parameters provided by the script."
	echo "Note that whatever you choose, all the choices presented in the script are safe. (Unlike OpenVPN's defaults)"
	echo "See https://github.com/angristan/openvpn-install#security-and-encryption to learn more."
	echo ""
	until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
		read -rp "Customize encryption settings? [y/n]: " -e -i n CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "n" ]];then
		# Use default, sane and fast parameters
		CIPHER="AES-128-GCM"
		CERT_TYPE="1" # ECDSA
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		DH_TYPE="1" # ECDH
		DH_CURVE="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="1" # tls-crypt
	else
		echo ""
		echo "Choose which cipher you want to use for the data channel:"
		echo "   1) AES-128-GCM (recommended)"
		echo "   2) AES-192-GCM"
		echo "   3) AES-256-GCM"
		echo "   4) AES-128-CBC"
		echo "   5) AES-192-CBC"
		echo "   6) AES-256-CBC"
		until [[ "$CIPHER_CHOICE" =~ ^[1-6]$ ]]; do
			read -rp "Cipher [1-6]: " -e -i 1 CIPHER_CHOICE
		done
		case $CIPHER_CHOICE in
			1)
				CIPHER="AES-128-GCM"
			;;
			2)
				CIPHER="AES-192-GCM"
			;;
			3)
				CIPHER="AES-256-GCM"
			;;
			4)
				CIPHER="AES-128-CBC"
			;;
			5)
				CIPHER="AES-192-CBC"
			;;
			6)
				CIPHER="AES-256-CBC"
			;;
		esac
		echo ""
		echo "Choose what kind of certificate you want to use:"
		echo "   1) ECDSA (recommended)"
		echo "   2) RSA"
		until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
			read -rp"Certificate key type [1-2]: " -e -i 1 CERT_TYPE
		done
		case $CERT_TYPE in
			1)
				echo ""
				echo "Choose which curve you want to use for the certificate's key:"
				echo "   1) prime256v1 (recommended)"
				echo "   2) secp384r1"
				echo "   3) secp521r1"
				until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
					read -rp"Curve [1-3]: " -e -i 1 CERT_CURVE_CHOICE
				done
				case $CERT_CURVE_CHOICE in
					1)
						CERT_CURVE="prime256v1"
					;;
					2)
						CERT_CURVE="secp384r1"
					;;
					3)
						CERT_CURVE="secp521r1"
					;;
				esac
			;;
			2)
				echo ""
				echo "Choose which size you want to use for the certificate's RSA key:"
				echo "   1) 2048 bits (recommended)"
				echo "   2) 3072 bits"
				echo "   3) 4096 bits"
				until [[ "$RSA_KEY_SIZE_CHOICE" =~ ^[1-3]$ ]]; do
					read -rp "RSA key size [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
				done
				case $RSA_KEY_SIZE_CHOICE in
					1)
						RSA_KEY_SIZE="2048"
					;;
					2)
						RSA_KEY_SIZE="3072"
					;;
					3)
						RSA_KEY_SIZE="4096"
					;;
				esac
			;;
		esac
		echo ""
		echo "Choose which cipher you want to use for the control channel:"
		case $CERT_TYPE in
			1)
				echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256 (recommended)"
				echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
				until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
					read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
				done
				case $CC_CIPHER_CHOICE in
					1)
						CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
					;;
					2)
						CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
					;;
				esac
			;;
			2)
				echo "   1) ECDHE-RSA-AES-128-GCM-SHA256 (recommended)"
				echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
				until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
					read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
				done
				case $CC_CIPHER_CHOICE in
					1)
						CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
					;;
					2)
						CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
					;;
				esac
			;;
		esac
		echo ""
		echo "Choose what kind of Diffie-Hellman key you want to use:"
		echo "   1) ECDH (recommended)"
		echo "   2) DH"
		until [[ $DH_TYPE =~ [1-2] ]]; do
			read -rp"DH key type [1-2]: " -e -i 1 DH_TYPE
		done
		case $DH_TYPE in
			1)
				echo ""
				echo "Choose which curve you want to use for the ECDH key:"
				echo "   1) prime256v1 (recommended)"
				echo "   2) secp384r1"
				echo "   3) secp521r1"
				while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
					read -rp"Curve [1-3]: " -e -i 1 DH_CURVE_CHOICE
				done
				case $DH_CURVE_CHOICE in
					1)
						DH_CURVE="prime256v1"
					;;
					2)
						DH_CURVE="secp384r1"
					;;
					3)
						DH_CURVE="secp521r1"
					;;
				esac
			;;
			2)
				echo ""
				echo "Choose what size of Diffie-Hellman key you want to use:"
				echo "   1) 2048 bits (recommended)"
				echo "   2) 3072 bits"
				echo "   3) 4096 bits"
				until [[ "$DH_KEY_SIZE_CHOICE" =~ ^[1-3]$ ]]; do
					read -rp "DH key size [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
				done
				case $DH_KEY_SIZE_CHOICE in
					1)
						DH_KEY_SIZE="2048"
					;;
					2)
						DH_KEY_SIZE="3072"
					;;
					3)
						DH_KEY_SIZE="4096"
					;;
				esac
			;;
		esac
		echo ""
		# The "auth" options behaves differently with AEAD ciphers
		if [[ "$CIPHER" =~ CBC$ ]]; then
			echo "The digest algorithm authenticates data channel packets and tls-auth packets from the control channel."
		elif [[ "$CIPHER" =~ GCM$ ]]; then
			echo "The digest algorithm authenticates tls-auth packets from the control channel."
		fi
		echo "Which digest algorithm do you want to use for HMAC?"
		echo "   1) SHA-256 (recommended)"
		echo "   2) SHA-384"
		echo "   3) SHA-512"
		until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "Digest algorithm [1-3]: " -e -i 1 HMAC_ALG_CHOICE
		done
		case $HMAC_ALG_CHOICE in
			1)
				HMAC_ALG="SHA256"
			;;
			2)
				HMAC_ALG="SHA384"
			;;
			3)
				HMAC_ALG="SHA512"
			;;
		esac
		echo ""
		echo "You can add an additional layer of security to the control channel with tls-auth and tls-crypt"
		echo "tls-auth authenticates the packets, while tls-crypt authenticate and encrypt them."
		echo "   1) tls-crypt (recommended)"
		echo "   2) tls-auth"
		until [[ $TLS_SIG =~ [1-2] ]]; do
				read -rp "Control channel additional security mechanism [1-2]: " -e -i 1 TLS_SIG
		done
	fi
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now."
	echo "You will be able to generate a client at the end of the installation."
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "Press any key to continue..."
	fi
}

function installPanel () {
	apt-get update -y && apt-get install apache2 php -y
	echo "Listen 8888
<IfModule ssl_module>
        Listen 443
</IfModule>
<IfModule mod_gnutls.c>
        Listen 443
</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet" > /etc/apache2/ports.conf
	service apache2 restart
	echo "<VirtualHost *:8888>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet" > /etc/apache2/sites-available/000-default.conf
	service apache2 restart
	echo "PD9waHAKZnVuY3Rpb24gYmpvcm4oJF9zdHJpbmcpewoJZWNobygkX3N0cmluZyk7Cn0KYmpvcm4oIjx0aXRsZT5Cam9yblZQTiB8IEFjY2VzcyBQYW5lbDwvdGl0bGU+Iik7CiRfZmlsZXMgPSBhcnJheV9kaWZmKHNjYW5kaXIoJF9TRVJWRVJbIkRPQ1VNRU5UX1JPT1QiXSksIGFycmF5KCIuIiwiLi4iLCJpbmRleC5waHAiKSk7CiRfeiA9IFtdOwpmb3JlYWNoKCRfZmlsZXMgYXMgJF9mKXsKCSRfeltdID0gKCI8YSBzdHlsZT0nVGV4dC1EZWNvcmF0aW9uOk5vbmU7Q3Vyc29yOlBvaW50ZXI7Q29sb3I6QmxhY2s7JyBocmVmPScvLyIuJF9TRVJWRVJbIkhUVFBfSE9TVCJdLiIvIi4kX2YuIj8iLnJhbmQoMTAwLDk5OTkpLiInPiIuJF9mLiI8L2E+Iik7Cn0KYmpvcm4oIjxjb2RlPjxwcmU+PGEgc3R5bGU9J1RleHQtRGVjb3JhdGlvbjpOb25lO0N1cnNvcjpQb2ludGVyO0NvbG9yOkJsYWNrOycgaHJlZj0nLy8iLiRfU0VSVkVSWyJIVFRQX0hPU1QiXS4iLz8iLnJhbmQoMTAwLDk5OTkpLiInPnJlZnJlc2ggcGFnZSAoICIuY291bnQoJF96KS4iIE9WUE5zICk8L2E+PGhyLz4iLmpvaW4oIjxoci8+IiwkX3opLiI8L3ByZT48L2NvZGU+Iik7Cj8+" | base64 --decode > /var/www/html/index.php
	service apache2 restart
	rm -r /var/www/html/index.html
	service apache2 restart
	chown -R ubuntu /var/www/html
	service apache2 restart
}

function installSquid () {
	apt-get update -y && apt-get install squid3 iftop -y
}

function installBjornServer () {
	if [[ $AUTO_INSTALL == "y" ]]; then
		APPROVE_INSTALL=${APPROVE_INSTALL:-y}
		APPROVE_IP=${APPROVE_IP:-y}
		IPV6_SUPPORT=${IPV6_SUPPORT:-n}
		PORT_CHOICE=${PORT_CHOICE:-1}
		PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
		DNS=${DNS:-1}
		COMPRESSION_ENABLED="y"
		CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
		CLIENT=${CLIENT:-client}
		PASS=${PASS:-1}
		CONTINUE=${CONTINUE:-y}

		# Behind NAT, we'll default to the publicly reachable IPv4.
		PUBLIC_IPV4=$(curl ifconfig.co)
		ENDPOINT=${ENDPOINT:-$PUBLIC_IPV4}
	fi

	# Run setup questions first, and set other variales if auto-install
	installQuestions

	# Get the "public" interface from the default route
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

	if [[ "$OS" =~ (debian|ubuntu) ]]; then
		apt-get update
		apt-get -y install ca-certificates gnupg
		# We add the OpenVPN repo to get the latest version.
		if [[ "$VERSION_ID" = "8" ]]; then
			echo "deb http://build.openvpn.net/debian/openvpn/stable jessie main" > /etc/apt/sources.list.d/openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		if [[ "$VERSION_ID" = "16.04" ]]; then
			echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" > /etc/apt/sources.list.d/openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		# Ubuntu > 16.04 and Debian > 8 have OpenVPN >= 2.4 without the need of a third party repository.
		apt-get install -y openvpn iptables openssl wget ca-certificates curl
	elif [[ "$OS" = 'centos' ]]; then
		yum install -y epel-release
		yum install -y openvpn iptables openssl wget ca-certificates curl
	elif [[ "$OS" = 'fedora' ]]; then
		dnf install -y openvpn iptables openssl wget ca-certificates curl
	elif [[ "$OS" = 'arch' ]]; then
		# Install required dependencies and upgrade the system
		pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl
	fi

	# Find out if the machine uses nogroup or nobody for the permissionless group
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi

	# An old version of easy-rsa was available by default in some openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi

	# Install the latest version of easy-rsa from source
	local version="3.0.6"
	wget -O ~/EasyRSA-unix-v${version}.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-unix-v${version}.tgz
	tar xzf ~/EasyRSA-unix-v${version}.tgz -C ~/
	mv ~/EasyRSA-v${version} /etc/openvpn/easy-rsa
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -f ~/EasyRSA-unix-v${version}.tgz

	cd /etc/openvpn/easy-rsa/
	case $CERT_TYPE in
		1)
			echo "set_var EASYRSA_ALGO ec" > vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >> vars
		;;
		2)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" > vars
		;;
	esac

	# Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
	SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	echo "set_var EASYRSA_REQ_CN $SERVER_CN" >> vars
	# Create the PKI, set up the CA, the DH params and the server certificate
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass

	if [[ $DH_TYPE == "2" ]]; then
		# ECDH keys are generated on-the-fly so we don't need to generate them beforehand
		openssl dhparam -out dh.pem $DH_KEY_SIZE
	fi

	./easyrsa build-server-full "$SERVER_NAME" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

	case $TLS_SIG in
		1)
			# Generate tls-crypt key
			openvpn --genkey --secret /etc/openvpn/tls-crypt.key
		;;
		2)
			# Generate tls-auth key
			openvpn --genkey --secret /etc/openvpn/tls-auth.key
		;;
	esac

	# Move all the generated files
	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	if [[ $DH_TYPE == "2" ]]; then
		cp dh.pem /etc/openvpn
	fi

	# Make cert revocation list readable for non-root
	chmod 644 /etc/openvpn/crl.pem

	# Generate server.conf
	echo "port $PORT" > /etc/openvpn/server.conf
	if [[ "$IPV6_SUPPORT" = 'n' ]]; then
		echo "proto $PROTOCOL" >> /etc/openvpn/server.conf
	elif [[ "$IPV6_SUPPORT" = 'y' ]]; then
		echo "proto ${PROTOCOL}6" >> /etc/openvpn/server.conf
	fi

	echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >> /etc/openvpn/server.conf

	# DNS resolvers
	case $DNS in
		1)
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep -q "127.0.0.53" "/etc/resolv.conf"; then
				RESOLVCONF='/run/systemd/resolve/resolv.conf'
			else
				RESOLVCONF='/etc/resolv.conf'
			fi
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 10.8.0.1"' >> /etc/openvpn/server.conf
		;;
		3) # Cloudflare
			echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
		;;
		4) # Quad9
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server.conf
		;;
		5) # Quad9 uncensored
			echo 'push "dhcp-option DNS 9.9.9.10"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 149.112.112.10"' >> /etc/openvpn/server.conf
		;;
		6) # FDN
			echo 'push "dhcp-option DNS 80.67.169.40"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 80.67.169.12"' >> /etc/openvpn/server.conf
		;;
		7) # DNS.WATCH
			echo 'push "dhcp-option DNS 84.200.69.80"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 84.200.70.40"' >> /etc/openvpn/server.conf
		;;
		8) # OpenDNS
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		9) # Google
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
		10) # Yandex Basic
			echo 'push "dhcp-option DNS 77.88.8.8"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 77.88.8.1"' >> /etc/openvpn/server.conf
		;;
		11) # AdGuard DNS
			echo 'push "dhcp-option DNS 176.103.130.130"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 176.103.130.131"' >> /etc/openvpn/server.conf
		;;
		12) # Custom DNS
			echo 'push "dhcp-option DNS 23.253.163.53"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 198.101.242.72"' >> /etc/openvpn/server.conf
		;;
	esac
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf

	# IPv6 network settings if needed
	if [[ "$IPV6_SUPPORT" = 'y' ]]; then
		echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"' >> /etc/openvpn/server.conf
	fi

	if [[ $COMPRESSION_ENABLED == "y"  ]]; then
		echo "compress $COMPRESSION_ALG" >> /etc/openvpn/server.conf
	fi

	if [[ $DH_TYPE == "1" ]]; then
		echo "dh none" >> /etc/openvpn/server.conf
		echo "ecdh-curve $DH_CURVE" >> /etc/openvpn/server.conf
	elif [[ $DH_TYPE == "2" ]]; then
		echo "dh dh.pem" >> /etc/openvpn/server.conf
	fi

	case $TLS_SIG in
		1)
			echo "tls-crypt tls-crypt.key 0" >> /etc/openvpn/server.conf
		;;
		2)
			echo "tls-auth tls-auth.key 0" >> /etc/openvpn/server.conf
		;;
	esac

	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
status /var/log/openvpn/status.log
verb 5" >> /etc/openvpn/server.conf

	# Create log dir
	mkdir -p /var/log/openvpn

	# Enable routing
	echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/20-openvpn.conf
	if [[ "$IPV6_SUPPORT" = 'y' ]]; then
		echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.d/20-openvpn.conf
	fi
	# Avoid an unneeded reboot
	sysctl --system

	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '465' ]]; then
				semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
			fi
		fi
	fi

	# Finally, restart and enable OpenVPN
	if [[ "$OS" = 'arch' || "$OS" = 'fedora' ]]; then
		# Don't modify package-provided service
		cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service

		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service
		# On fedora, the service hardcodes the ciphers. We want to manage the cipher ourselves, so we remove it from the service
		if [[ "$OS" == "fedora" ]];then
			sed -i 's|--cipher AES-256-GCM --ncp-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC:BF-CBC||' /etc/systemd/system/openvpn-server@.service
		fi

		systemctl daemon-reload
		systemctl restart openvpn-server@server
		systemctl enable openvpn-server@server
	elif [[ "$OS" == "ubuntu" ]] && [[ "$VERSION_ID" == "16.04" ]]; then
		# On Ubuntu 16.04, we use the package from the OpenVPN repo
		# This package uses a sysvinit service
		systemctl enable openvpn
		systemctl start openvpn
	else
		# Don't modify package-provided service
		cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service

		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service

		systemctl daemon-reload
		systemctl restart openvpn@server
		systemctl enable openvpn@server
	fi

	if [[ $DNS == 2 ]];then
		installUnbound
	fi

	# Add iptables rules in two scripts
	mkdir /etc/iptables

	# Script to add rules
	echo "#!/bin/sh
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -A INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" > /etc/iptables/add-openvpn-rules.sh

	if [[ "$IPV6_SUPPORT" = 'y' ]]; then
		echo "ip6tables -t nat -A POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -A INPUT -i tun0 -j ACCEPT
ip6tables -A FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -A FORWARD -i tun0 -o $NIC -j ACCEPT" >> /etc/iptables/add-openvpn-rules.sh
	fi

	# Script to remove rules
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" > /etc/iptables/rm-openvpn-rules.sh

	if [[ "$IPV6_SUPPORT" = 'y' ]]; then
		echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT" >> /etc/iptables/rm-openvpn-rules.sh
	fi

	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh

	# Handle the rules via a systemd script
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/iptables-openvpn.service

	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn

	# If the server is behind a NAT, use the correct IP address for the clients to connect to
	if [[ "$ENDPOINT" != "" ]]; then
		IP=$ENDPOINT
	fi

	# client-template.md is created so we have a template to add further users later
	echo "# Made by BjornVPN and OpenSSH with ShadowSocksR Panel" > /etc/openvpn/client-template.md
	echo "" >> /etc/openvpn/client-template.md
	echo "client" >> /etc/openvpn/client-template.md
	if [[ "$PROTOCOL" = 'tcp' ]]; then
		echo "proto tcp" >> /etc/openvpn/client-template.md
	elif [[ "$PROTOCOL" = 'udp' ]]; then
		echo "proto udp" >> /etc/openvpn/client-template.md
	fi
	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
setenv opt block-outside-dns
keepalive 2 60" >> /etc/openvpn/client-template.md

if [[ $COMPRESSION_ENABLED == "y"  ]]; then
	echo "compress $COMPRESSION_ALG" >> /etc/openvpn/client-template.md
	echo "verb 5" >> /etc/openvpn/client-template.md
	echo "pull" >> /etc/openvpn/client-template.md
fi
	defaultAccount
	echo "If you want to add more clients, you simply need to run this script another time!"
}

function createConfig () {
	echo ""
	echo "Tell me a name for the Account Setup."
	echo "Use one word only, no special characters."

	until [[ "$CLIENT" =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Account Config Name: " -e CLIENT
	done

	echo ""
	echo "Do you have a Voucher Code?"
	echo ""
	echo "	1) Lifetime without Voucher Account."
	echo "	2) Use a Generated Voucher for the Config."
	until [[ "$PASS" =~ ^[1-2]$ ]]; do
		read -rp "Select an Option [1-2]: " -e -i 1 PASS
	done

	until [[ "$METHOD" =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Payload Method [POST, GET, PUT, TRACE, CONNECT]: " -e METHOD
	done
	
	until [[ "$PAYLOAD" =~ ^[a-zA-Z0-9_.]+$ ]]; do
		read -rp "Payload HOST [HTTPs, HTTP]: " -e PAYLOAD
	done

	cd /etc/openvpn/easy-rsa/ || return
	case $PASS in
		1)
			./easyrsa build-client-full "$CLIENT" nopass
			clear
		;;
		2)
		echo "You will be asked for the Config Voucher below:"
			./easyrsa build-client-full "$CLIENT"
			clear
		;;
	esac

	# Home directory of the user, where the client configuration (.ovpn) will be written
	if [ -e "/var/www/html" ]; then  # if $1 is a user name
		homeDir="/var/www/html"
	elif [ "${SUDO_USER}" ]; then   # if not, use SUDO_USER
		homeDir="/var/www/html"
	else  # if not SUDO_USER, use /root
		homeDir="/var/www/html"
	fi

	# Determine if we use tls-auth or tls-crypt
	if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
		TLS_SIG="1"
		clear
	elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
		TLS_SIG="2"
		clear
	fi

	# Generates the custom client.ovpn
	cp /etc/openvpn/client-template.md "$homeDir/$CLIENT.ovpn"
	{
		echo ""
		echo "http-proxy $IP ${squidPORTS[$SquidGEN]}
http-proxy-option CUSTOM-HEADER '$METHOD https://$PAYLOAD HTTP/1.0'
http-proxy-option CUSTOM-HEADER 'Host: $PAYLOAD'
http-proxy-option CUSTOM-HEADER 'Proxy-Connection: Keep-Alive'
http-proxy-option CUSTOM-HEADER 'Connection: Keep-Alive'"
		echo "dhcp-option DNS 23.253.163.53"
		echo "dhcp-option DNS 198.101.242.72"
		echo ""
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"
		echo "<cert>"
		awk '/BEGIN/,/END/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
		echo "</cert>"
		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
		echo "</key>"

		case $TLS_SIG in
			1)
				echo "<tls-crypt>"
				cat "/etc/openvpn/tls-crypt.key"
				echo "</tls-crypt>"
			;;
			2)
				echo "key-direction 1"
				echo "<tls-auth>"
				cat "/etc/openvpn/tls-auth.key"
				echo "</tls-auth>"
			;;
		esac
	} >> "$homeDir/$CLIENT.ovpn"

	clear
	echo "Account: $CLIENT Generated edit it via $homeDir/$CLIENT.ovpn!"
	echo "You can now Download the BjornVPN Account via the Web Panel $IP:8888!"
	exit 0
}

function removeConfig () {
	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
		echo ""
		echo "You have no Existing Accounts!"
		exit 1
	fi

	echo ""
	echo "Select the Existing Account certificate you want to revoke"
	tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
		read -rp "Select one client [1]: " CLIENTNUMBER
	else
		read -rp "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
	fi

	CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
	cd /etc/openvpn/easy-rsa/
	./easyrsa --batch revoke "$CLIENT"
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Cleanup
	rm -f "pki/reqs/$CLIENT.req"
	rm -f "pki/private/$CLIENT.key"
	rm -f "pki/issued/$CLIENT.crt"
	rm -f "/etc/openvpn/crl.pem"
	cp "/etc/openvpn/easy-rsa/pki/crl.pem" "/etc/openvpn/crl.pem"
	chmod 644 "/etc/openvpn/crl.pem"
	find "/var/www/html/" -maxdepth 2 -name "$CLIENT.ovpn" -delete
	rm -f "/var/www/html/$CLIENT.ovpn"
	sed -i "s|^$CLIENT,.*||" "/etc/openvpn/ipp.txt"
	manageMenu
}

function removeUnbound () {
	# Remove OpenVPN-related config
	sed -i 's|include: \/etc\/unbound\/openvpn.conf||' /etc/unbound/unbound.conf
	rm /etc/unbound/openvpn.conf
	systemctl restart unbound

	until [[ $REMOVE_UNBOUND =~ (y|n) ]]; do
		echo ""
		echo "If you were already using Unbound before installing OpenVPN, I removed the configuration related to OpenVPN."
		read -rp "Do you want to completely remove Unbound? [y/n]: " -e REMOVE_UNBOUND
	done

	if [[ "$REMOVE_UNBOUND" = 'y' ]]; then
		# Stop Unbound
		systemctl stop unbound

		if [[ "$OS" =~ (debian|ubuntu) ]]; then
			apt-get autoremove --purge -y unbound
		elif [[ "$OS" = 'arch' ]]; then
			pacman --noconfirm -R unbound
		elif [[ "$OS" = 'centos' ]]; then
			yum remove -y unbound
		elif [[ "$OS" = 'fedora' ]]; then
			dnf remove -y unbound
		fi

		rm -rf /etc/unbound/

		echo ""
		echo "Unbound removed!"
	else
		echo ""
		echo "Unbound wasn't removed."
	fi
}

function removeBjornVPN () {
	echo ""
	read -rp "Do you really want to remove BjornVPN? [y/n]: " -e -i y REMOVE
	if [[ "$REMOVE" = 'y' ]]; then
		# Get OpenVPN port from the configuration
		PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)

		# Stop OpenVPN
		if [[ "$OS" =~ (fedora|arch) ]]; then
			systemctl disable openvpn-server@server
			systemctl stop openvpn-server@server
			# Remove customised service
			rm /etc/systemd/system/openvpn-server@.service
		elif [[ "$OS" == "ubuntu" ]] && [[ "$VERSION_ID" == "16.04" ]]; then
			systemctl disable openvpn
			systemctl stop openvpn
		else
			systemctl disable openvpn@server
			systemctl stop openvpn@server
			# Remove customised service
			rm /etc/systemd/system/openvpn\@.service
		fi

		# Remove the iptables rules related to the script
		systemctl stop iptables-openvpn
		# Cleanup
		systemctl disable iptables-openvpn
		rm /etc/systemd/system/iptables-openvpn.service
		systemctl daemon-reload
		rm /etc/iptables/add-openvpn-rules.sh
		rm /etc/iptables/rm-openvpn-rules.sh

		# SELinux
		if hash sestatus 2>/dev/null; then
			if sestatus | grep "Current mode" | grep -qs "enforcing"; then
				if [[ "$PORT" != '465' ]]; then
					semanage port -d -t openvpn_port_t -p udp "$PORT"
				fi
			fi
		fi

		if [[ "$OS" =~ (debian|ubuntu) ]]; then
			apt-get autoremove --purge -y openvpn
			if [[ -e /etc/apt/sources.list.d/openvpn.list ]];then
				rm /etc/apt/sources.list.d/openvpn.list
				apt-get update
			fi
		elif [[ "$OS" = 'arch' ]]; then
			pacman --noconfirm -R openvpn
		elif [[ "$OS" = 'centos' ]]; then
			yum remove -y openvpn
		elif [[ "$OS" = 'fedora' ]]; then
			dnf remove -y openvpn
		fi

		# Cleanup
		find /home/ -maxdepth 2 -name "*.ovpn" -delete
		find /root/ -maxdepth 1 -name "*.ovpn" -delete
		rm -rf /etc/openvpn
		rm -rf /usr/share/doc/openvpn*
		rm -f /etc/sysctl.d/20-openvpn.conf
		rm -rf /var/log/openvpn

		# Unbound
		if [[ -e /etc/unbound/openvpn.conf ]]; then
			removeUnbound
		fi
		echo ""
		echo "BjornVPN removed!"
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function updateInstaller () {
	curl -O https://raw.githubusercontent.com/sshwispio/bjornvpn/master/io.sh && chmod o+x io.sh && ./io.sh
	exit 0
}

function manageMenu () {
	clear
	echo "Welcome to BjornVPN!"
	echo ""
	echo "It looks like BjornVPN is already installed."
	echo ""
	echo "BjornVPN OpenVPN Port: 465, Squid Proxy Port ${squidPORTS[0]}/${squidPORTS[1]}/${squidPORTS[2]}/${squidPORTS[3]}/${squidPORTS[4]}/${squidPORTS[5]}"
	echo "To add a New User do choose Option 1:1 for Passwordless Client Configurations!"
	echo ""
	echo "What do you want to do?"
	echo "		1) Add a New User Account"
	echo "		2) Remove Existing User Account"
	echo "		3) Remove BjornVPN Installation"
	echo "		4) Update BjornVPN Installer"
	echo "		5) Refresh BjornVPN Banner"
	echo "		6) Exit BjornVPN Installer"
	until [[ "$MENU_OPTION" =~ ^[1-5]$ ]]; do
		read -rp "Select a Menu Option [1-5]: " MENU_OPTION
	done

	case $MENU_OPTION in
		1)
			createConfig
		;;
		2)
			removeConfig
		;;
		3)
			removeBjornVPN
		;;
		4)
			updateInstaller
		;;
		5)
			setupBanner
		;;
		6)
			exit 0
		;;
	esac
}

function setupBanner () {
	clear
	echo "# Modified BjornVPN Squid Proxy

	acl SSL_ports port 443
	acl Safe_ports port 80
	acl Safe_ports port 21
	acl Safe_ports port 443
	acl Safe_ports port 70
	acl Safe_ports port 210
	acl Safe_ports port 1025-65535
	acl Safe_ports port 280
	acl Safe_ports port 488
	acl Safe_ports port 591
	acl Safe_ports port 777
	acl CONNECT method CONNECT

	http_access allow !Safe_ports

	http_access allow CONNECT !SSL_ports

	http_access allow localhost manager
	http_access allow manager

	http_access allow localhost

	http_access allow all

	http_port ${squidPORTS[0]}
	http_port ${squidPORTS[1]}
	http_port ${squidPORTS[2]}
	http_port ${squidPORTS[3]}
	http_port ${squidPORTS[4]}
	http_port ${squidPORTS[5]}

	coredump_dir /var/spool/squid" > /etc/squid/squid.conf
	clear
	service squid restart
	clear
	echo "BjornVPN OpenVPN Port: 465
	BjornVPN Squid Proxy Port: ${squidPORTS[0]}/${squidPORTS[1]}/${squidPORTS[2]}/${squidPORTS[3]}/${squidPORTS[4]}/${squidPORTS[5]}
	BjornVPN Web Panel Access: $IP:8888
	BjornVPN Made by: Xin Snowflakes
	Admin Contact Number - (PayMaya and GCash) - for Donation: 09225205353
	Admin Contact For Bugs: Use these Contacts, Admin Email and Admin Number
	Admin Email: binarykorra@icloud.com
	Admin Panel Version: 0.002" > /root/template.md
	sed -i '/Banner/a Banner="/root/template.md"' /etc/ssh/sshd_config
	service sshd restart
	clear
	echo "BjornVPN OpenVPN Port: 465
	BjornVPN Squid Proxy Port: ${squidPORTS[0]}/${squidPORTS[1]}/${squidPORTS[2]}/${squidPORTS[3]}/${squidPORTS[4]}/${squidPORTS[5]}
	BjornVPN Web Panel Access: $IP:8888
	BjornVPN Made by: Xin Snowflakes
	Admin Contact Number - (PayMaya and GCash) - for Donation: 09225205353
	Admin Contact For Bugs: Use these Contacts, Admin Email and Admin Number
	Admin Email: binarykorra@icloud.com
	Admin Panel Version: 0.002"
	service sshd restart
	exit 0
}

initialCheck
# Initial Setup
SquidGEN=$(shuf -i 0-5 -n1)
IP=$(curl -4 icanhazip.com)

declare -a squidPORTS=("8000" "3128" "1337" "1338" "8080" "1336")
if [[ -e /etc/openvpn/server.conf ]]; then
	manageMenu
else
	installSquid
	installPanel
	installBjornServer
fi
