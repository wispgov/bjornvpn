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
	
	if [ -e "/var/www/html/panel" ]; then
		homeDir="/var/www/html/panel"
	elif [ "${SUDO_USER}" ]; then
		homeDir="/var/www/html/panel"
	else
		homeDir="/var/www/html/panel"
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
		read -rp"Enable Compression? [y/n]: " -e -i n COMPRESSION_ENABLED
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
	sudo add-apt-repository ppa:ondrej/php -y && apt-get update --fix-missing -y && apt-get update -y
	sudo apt-get update -y && apt-get install apache2 php-http-request php5.6-dev php5.6 re2c gcc make git php-memcached memcached -y
	service apache2 restart
	mkdir "/var/www/html/panel"
	service apache2 restart
	sudo a2enmod rewrite
	service apache2 restart
	echo "Listen 6060
<IfModule ssl_module>
        Listen 443
</IfModule>
<IfModule mod_gnutls.c>
        Listen 443
</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet" > /etc/apache2/ports.conf
	service apache2 restart
	echo "RewriteEngine On
RewriteBase /
	
DirectoryIndex 110011.bjorn
RewriteRule ^admin/([0-9]+)/$ 110011.bjorn?gen=$1 [NC]

<FilesMatch '\.(bjorn)$'>
        ForceType application/x-httpd-php
</FilesMatch>

<FilesMatch '\.(ovpn)$'>
        ForceType application/json
</FilesMatch>" > /var/www/html/panel/.htaccess
	echo "<VirtualHost *:6060>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html/panel
		<Directory /var/www/html/panel>
			Options Indexes FollowSymLinks MultiViews
			AllowOverride All
			Order allow,deny
			allow from all
		</Directory>
        ErrorLog /root/error.log
        CustomLog /root/access.log combined
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet" > /etc/apache2/sites-available/000-default.conf
	service apache2 restart
	echo "PD9waHAKLyoqCiAqIFBFQVIgYW5kIFBFQVJfRXJyb3IgY2xhc3NlcyAoZm9yIGVycm9yIGhhbmRsaW5nKQogKi8KcmVxdWlyZV9vbmNlICdQRUFSLnBocCc7Ci8qKgogKiBTb2NrZXQgY2xhc3MKICovCnJlcXVpcmVfb25jZSAnTmV0L1NvY2tldC5waHAnOwovKioKICogVVJMIGhhbmRsaW5nIGNsYXNzCiAqLwpyZXF1aXJlX29uY2UgJ05ldC9VUkwucGhwJzsKCi8qKiNAKwogKiBDb25zdGFudHMgZm9yIEhUVFAgcmVxdWVzdCBtZXRob2RzCiAqLwpkZWZpbmUoJ0hUVFBfUkVRVUVTVF9NRVRIT0RfR0VUJywgICAgICdHRVQnLCAgICAgdHJ1ZSk7CmRlZmluZSgnSFRUUF9SRVFVRVNUX01FVEhPRF9IRUFEJywgICAgJ0hFQUQnLCAgICB0cnVlKTsKZGVmaW5lKCdIVFRQX1JFUVVFU1RfTUVUSE9EX1BPU1QnLCAgICAnUE9TVCcsICAgIHRydWUpOwpkZWZpbmUoJ0hUVFBfUkVRVUVTVF9NRVRIT0RfUFVUJywgICAgICdQVVQnLCAgICAgdHJ1ZSk7CmRlZmluZSgnSFRUUF9SRVFVRVNUX01FVEhPRF9ERUxFVEUnLCAgJ0RFTEVURScsICB0cnVlKTsKZGVmaW5lKCdIVFRQX1JFUVVFU1RfTUVUSE9EX09QVElPTlMnLCAnT1BUSU9OUycsIHRydWUpOwpkZWZpbmUoJ0hUVFBfUkVRVUVTVF9NRVRIT0RfVFJBQ0UnLCAgICdUUkFDRScsICAgdHJ1ZSk7Ci8qKiNALSovCgovKiojQCsKICogQ29uc3RhbnRzIGZvciBIVFRQIHJlcXVlc3QgZXJyb3IgY29kZXMKICovCmRlZmluZSgnSFRUUF9SRVFVRVNUX0VSUk9SX0ZJTEUnLCAgICAgICAgICAgICAxKTsKZGVmaW5lKCdIVFRQX1JFUVVFU1RfRVJST1JfVVJMJywgICAgICAgICAgICAgIDIpOwpkZWZpbmUoJ0hUVFBfUkVRVUVTVF9FUlJPUl9QUk9YWScsICAgICAgICAgICAgNCk7CmRlZmluZSgnSFRUUF9SRVFVRVNUX0VSUk9SX1JFRElSRUNUUycsICAgICAgICA4KTsKZGVmaW5lKCdIVFRQX1JFUVVFU1RfRVJST1JfUkVTUE9OU0UnLCAgICAgICAgMTYpOwpkZWZpbmUoJ0hUVFBfUkVRVUVTVF9FUlJPUl9HWklQX01FVEhPRCcsICAgICAzMik7CmRlZmluZSgnSFRUUF9SRVFVRVNUX0VSUk9SX0daSVBfUkVBRCcsICAgICAgIDY0KTsKZGVmaW5lKCdIVFRQX1JFUVVFU1RfRVJST1JfR1pJUF9EQVRBJywgICAgICAxMjgpOwpkZWZpbmUoJ0hUVFBfUkVRVUVTVF9FUlJPUl9HWklQX0NSQycsICAgICAgIDI1Nik7Ci8qKiNALSovCgovKiojQCsKICogQ29uc3RhbnRzIGZvciBIVFRQIHByb3RvY29sIHZlcnNpb25zCiAqLwpkZWZpbmUoJ0hUVFBfUkVRVUVTVF9IVFRQX1ZFUl8xXzAnLCAnMS4wJywgdHJ1ZSk7CmRlZmluZSgnSFRUUF9SRVFVRVNUX0hUVFBfVkVSXzFfMScsICcxLjEnLCB0cnVlKTsKLyoqI0AtKi8KCmlmIChleHRlbnNpb25fbG9hZGVkKCdtYnN0cmluZycpICYmICgyICYgaW5pX2dldCgnbWJzdHJpbmcuZnVuY19vdmVybG9hZCcpKSkgewogICAvKioKICAgICogV2hldGhlciBzdHJpbmcgZnVuY3Rpb25zIGFyZSBvdmVybG9hZGVkIGJ5IHRoZWlyIG1ic3RyaW5nIGVxdWl2YWxlbnRzCiAgICAqLwogICAgZGVmaW5lKCdIVFRQX1JFUVVFU1RfTUJTVFJJTkcnLCB0cnVlKTsKfSBlbHNlIHsKICAgLyoqCiAgICAqIEBpZ25vcmUKICAgICovCiAgICBkZWZpbmUoJ0hUVFBfUkVRVUVTVF9NQlNUUklORycsIGZhbHNlKTsKfQoKLyoqCiAqIENsYXNzIGZvciBwZXJmb3JtaW5nIEhUVFAgcmVxdWVzdHMKICoKICogU2ltcGxlIGV4YW1wbGUgKGZldGNoZXMgeWFob28uY29tIGFuZCBkaXNwbGF5cyBpdCk6CiAqIDxjb2RlPgogKiAkYSA9ICZuZXcgSFRUUF9SZXF1ZXN0KCdodHRwOi8vd3d3LnlhaG9vLmNvbS8nKTsKICogJGEtPnNlbmRSZXF1ZXN0KCk7CiAqIGVjaG8gJGEtPmdldFJlc3BvbnNlQm9keSgpOwogKiA8L2NvZGU+CiAqCiAqIEBjYXRlZ29yeSAgICBIVFRQCiAqIEBwYWNrYWdlICAgICBIVFRQX1JlcXVlc3QKICogQGF1dGhvciAgICAgIFJpY2hhcmQgSGV5ZXMgPHJpY2hhcmRAcGhwZ3VydS5vcmc+CiAqIEBhdXRob3IgICAgICBBbGV4ZXkgQm9yem92IDxhdmJAcGhwLm5ldD4KICogQHZlcnNpb24gICAgIFJlbGVhc2U6IDEuNC40CiAqLwpjbGFzcyBIVFRQX1JlcXVlc3QKewogICAvKiojQCsKICAgICogQGFjY2VzcyBwcml2YXRlCiAgICAqLwogICAgLyoqCiAgICAqIEluc3RhbmNlIG9mIE5ldF9VUkwKICAgICogQHZhciBOZXRfVVJMCiAgICAqLwogICAgdmFyICRfdXJsOwoKICAgIC8qKgogICAgKiBUeXBlIG9mIHJlcXVlc3QKICAgICogQHZhciBzdHJpbmcKICAgICovCiAgICB2YXIgJF9tZXRob2Q7CgogICAgLyoqCiAgICAqIEhUVFAgVmVyc2lvbgogICAgKiBAdmFyIHN0cmluZwogICAgKi8KICAgIHZhciAkX2h0dHA7CgogICAgLyoqCiAgICAqIFJlcXVlc3QgaGVhZGVycwogICAgKiBAdmFyIGFycmF5CiAgICAqLwogICAgdmFyICRfcmVxdWVzdEhlYWRlcnM7CgogICAgLyoqCiAgICAqIEJhc2ljIEF1dGggVXNlcm5hbWUKICAgICogQHZhciBzdHJpbmcKICAgICovCiAgICB2YXIgJF91c2VyOwoKICAgIC8qKgogICAgKiBCYXNpYyBBdXRoIFBhc3N3b3JkCiAgICAqIEB2YXIgc3RyaW5nCiAgICAqLwogICAgdmFyICRfcGFzczsKCiAgICAvKioKICAgICogU29ja2V0IG9iamVjdAogICAgKiBAdmFyIE5ldF9Tb2NrZXQKICAgICovCiAgICB2YXIgJF9zb2NrOwoKICAgIC8qKgogICAgKiBQcm94eSBzZXJ2ZXIKICAgICogQHZhciBzdHJpbmcKICAgICovCiAgICB2YXIgJF9wcm94eV9ob3N0OwoKICAgIC8qKgogICAgKiBQcm94eSBwb3J0CiAgICAqIEB2YXIgaW50ZWdlcgogICAgKi8KICAgIHZhciAkX3Byb3h5X3BvcnQ7CgogICAgLyoqCiAgICAqIFByb3h5IHVzZXJuYW1lCiAgICAqIEB2YXIgc3RyaW5nCiAgICAqLwogICAgdmFyICRfcHJveHlfdXNlcjsKCiAgICAvKioKICAgICogUHJveHkgcGFzc3dvcmQKICAgICogQHZhciBzdHJpbmcKICAgICovCiAgICB2YXIgJF9wcm94eV9wYXNzOwoKICAgIC8qKgogICAgKiBQb3N0IGRhdGEKICAgICogQHZhciBhcnJheQogICAgKi8KICAgIHZhciAkX3Bvc3REYXRhOwoKICAgLyoqCiAgICAqIFJlcXVlc3QgYm9keQogICAgKiBAdmFyIHN0cmluZwogICAgKi8KICAgIHZhciAkX2JvZHk7CgogICAvKioKICAgICogQSBsaXN0IG9mIG1ldGhvZHMgdGhhdCBNVVNUIE5PVCBoYXZlIGEgcmVxdWVzdCBib2R5LCBwZXIgUkZDIDI2MTYKICAgICogQHZhciBhcnJheQogICAgKi8KICAgIHZhciAkX2JvZHlEaXNhbGxvd2VkID0gYXJyYXkoJ1RSQUNFJyk7CgogICAvKioKICAgICogTWV0aG9kcyBoYXZpbmcgZGVmaW5lZCBzZW1hbnRpY3MgZm9yIHJlcXVlc3QgYm9keQogICAgKgogICAgKiBDb250ZW50LUxlbmd0aCBoZWFkZXIgKGluZGljYXRpbmcgdGhhdCB0aGUgYm9keSBmb2xsb3dzLCBzZWN0aW9uIDQuMyBvZgogICAgKiBSRkMgMjYxNikgd2lsbCBiZSBzZW50IGZvciB0aGVzZSBtZXRob2RzIGV2ZW4gaWYgbm8gYm9keSB3YXMgYWRkZWQKICAgICoKICAgICogQHZhciBhcnJheQogICAgKi8KICAgIHZhciAkX2JvZHlSZXF1aXJlZCA9IGFycmF5KCdQT1NUJywgJ1BVVCcpOwoKICAgLyoqCiAgICAqIEZpbGVzIHRvIHBvc3QKICAgICogQHZhciBhcnJheQogICAgKi8KICAgIHZhciAkX3Bvc3RGaWxlcyA9IGFycmF5KCk7CgogICAgLyoqCiAgICAqIENvbm5lY3Rpb24gdGltZW91dC4KICAgICogQHZhciBmbG9hdAogICAgKi8KICAgIHZhciAkX3RpbWVvdXQ7CgogICAgLyoqCiAgICAqIEhUVFBfUmVzcG9uc2Ugb2JqZWN0CiAgICAqIEB2YXIgSFRUUF9SZXNwb25zZQogICAgKi8KICAgIHZhciAkX3Jlc3BvbnNlOwoKICAgIC8qKgogICAgKiBXaGV0aGVyIHRvIGFsbG93IHJlZGlyZWN0cwogICAgKiBAdmFyIGJvb2xlYW4KICAgICovCiAgICB2YXIgJF9hbGxvd1JlZGlyZWN0czsKCiAgICAvKioKICAgICogTWF4aW11bSByZWRpcmVjdHMgYWxsb3dlZAogICAgKiBAdmFyIGludGVnZXIKICAgICovCiAgICB2YXIgJF9tYXhSZWRpcmVjdHM7CgogICAgLyoqCiAgICAqIEN1cnJlbnQgbnVtYmVyIG9mIHJlZGlyZWN0cwogICAgKiBAdmFyIGludGVnZXIKICAgICovCiAgICB2YXIgJF9yZWRpcmVjdHM7CgogICAvKioKICAgICogV2hldGhlciB0byBhcHBlbmQgYnJhY2tldHMgW10gdG8gYXJyYXkgdmFyaWFibGVzCiAgICAqIEB2YXIgYm9vbAogICAgKi8KICAgIHZhciAkX3VzZUJyYWNrZXRzID0gdHJ1ZTsKCiAgIC8qKgogICAgKiBBdHRhY2hlZCBsaXN0ZW5lcnMKICAgICogQHZhciBhcnJheQogICAgKi8KICAgIHZhciAkX2xpc3RlbmVycyA9IGFycmF5KCk7CgogICAvKioKICAgICogV2hldGhlciB0byBzYXZlIHJlc3BvbnNlIGJvZHkgaW4gcmVzcG9uc2Ugb2JqZWN0IHByb3BlcnR5CiAgICAqIEB2YXIgYm9vbAogICAgKi8KICAgIHZhciAkX3NhdmVCb2R5ID0gdHJ1ZTsKCiAgIC8qKgogICAgKiBUaW1lb3V0IGZvciByZWFkaW5nIGZyb20gc29ja2V0IChhcnJheShzZWNvbmRzLCBtaWNyb3NlY29uZHMpKQogICAgKiBAdmFyIGFycmF5CiAgICAqLwogICAgdmFyICRfcmVhZFRpbWVvdXQgPSBudWxsOwoKICAgLyoqCiAgICAqIE9wdGlvbnMgdG8gcGFzcyB0byBOZXRfU29ja2V0Ojpjb25uZWN0LiBTZWUgc3RyZWFtX2NvbnRleHRfY3JlYXRlCiAgICAqIEB2YXIgYXJyYXkKICAgICovCiAgICB2YXIgJF9zb2NrZXRPcHRpb25zID0gbnVsbDsKICAgLyoqI0AtKi8KCiAgICAvKioKICAgICogQ29uc3RydWN0b3IKICAgICoKICAgICogU2V0cyB1cCB0aGUgb2JqZWN0CiAgICAqIEBwYXJhbSAgICBzdHJpbmcgIFRoZSB1cmwgdG8gZmV0Y2gvYWNjZXNzCiAgICAqIEBwYXJhbSAgICBhcnJheSAgIEFzc29jaWF0aXZlIGFycmF5IG9mIHBhcmFtZXRlcnMgd2hpY2ggY2FuIGhhdmUgdGhlIGZvbGxvd2luZyBrZXlzOgogICAgKiA8dWw+CiAgICAqICAgPGxpPm1ldGhvZCAgICAgICAgIC0gTWV0aG9kIHRvIHVzZSwgR0VULCBQT1NUIGV0YyAoc3RyaW5nKTwvbGk+CiAgICAqICAgPGxpPmh0dHAgICAgICAgICAgIC0gSFRUUCBWZXJzaW9uIHRvIHVzZSwgMS4wIG9yIDEuMSAoc3RyaW5nKTwvbGk+CiAgICAqICAgPGxpPnVzZXIgICAgICAgICAgIC0gQmFzaWMgQXV0aCB1c2VybmFtZSAoc3RyaW5nKTwvbGk+CiAgICAqICAgPGxpPnBhc3MgICAgICAgICAgIC0gQmFzaWMgQXV0aCBwYXNzd29yZCAoc3RyaW5nKTwvbGk+CiAgICAqICAgPGxpPnByb3h5X2hvc3QgICAgIC0gUHJveHkgc2VydmVyIGhvc3QgKHN0cmluZyk8L2xpPgogICAgKiAgIDxsaT5wcm94eV9wb3J0ICAgICAtIFByb3h5IHNlcnZlciBwb3J0IChpbnRlZ2VyKTwvbGk+CiAgICAqICAgPGxpPnByb3h5X3VzZXIgICAgIC0gUHJveHkgYXV0aCB1c2VybmFtZSAoc3RyaW5nKTwvbGk+CiAgICAqICAgPGxpPnByb3h5X3Bhc3MgICAgIC0gUHJveHkgYXV0aCBwYXNzd29yZCAoc3RyaW5nKTwvbGk+CiAgICAqICAgPGxpPnRpbWVvdXQgICAgICAgIC0gQ29ubmVjdGlvbiB0aW1lb3V0IGluIHNlY29uZHMgKGZsb2F0KTwvbGk+CiAgICAqICAgPGxpPmFsbG93UmVkaXJlY3RzIC0gV2hldGhlciB0byBmb2xsb3cgcmVkaXJlY3RzIG9yIG5vdCAoYm9vbCk8L2xpPgogICAgKiAgIDxsaT5tYXhSZWRpcmVjdHMgICAtIE1heCBudW1iZXIgb2YgcmVkaXJlY3RzIHRvIGZvbGxvdyAoaW50ZWdlcik8L2xpPgogICAgKiAgIDxsaT51c2VCcmFja2V0cyAgICAtIFdoZXRoZXIgdG8gYXBwZW5kIFtdIHRvIGFycmF5IHZhcmlhYmxlIG5hbWVzIChib29sKTwvbGk+CiAgICAqICAgPGxpPnNhdmVCb2R5ICAgICAgIC0gV2hldGhlciB0byBzYXZlIHJlc3BvbnNlIGJvZHkgaW4gcmVzcG9uc2Ugb2JqZWN0IHByb3BlcnR5IChib29sKTwvbGk+CiAgICAqICAgPGxpPnJlYWRUaW1lb3V0ICAgIC0gVGltZW91dCBmb3IgcmVhZGluZyAvIHdyaXRpbmcgZGF0YSBvdmVyIHRoZSBzb2NrZXQgKGFycmF5IChzZWNvbmRzLCBtaWNyb3NlY29uZHMpKTwvbGk+CiAgICAqICAgPGxpPnNvY2tldE9wdGlvbnMgIC0gT3B0aW9ucyB0byBwYXNzIHRvIE5ldF9Tb2NrZXQgb2JqZWN0IChhcnJheSk8L2xpPgogICAgKiA8L3VsPgogICAgKiBAYWNjZXNzIHB1YmxpYwogICAgKi8KICAgIGZ1bmN0aW9uIEhUVFBfUmVxdWVzdCgkdXJsID0gJycsICRwYXJhbXMgPSBhcnJheSgpKQogICAgewogICAgICAgICR0aGlzLT5fbWV0aG9kICAgICAgICAgPSAgSFRUUF9SRVFVRVNUX01FVEhPRF9HRVQ7CiAgICAgICAgJHRoaXMtPl9odHRwICAgICAgICAgICA9ICBIVFRQX1JFUVVFU1RfSFRUUF9WRVJfMV8xOwogICAgICAgICR0aGlzLT5fcmVxdWVzdEhlYWRlcnMgPSBhcnJheSgpOwogICAgICAgICR0aGlzLT5fcG9zdERhdGEgICAgICAgPSBhcnJheSgpOwogICAgICAgICR0aGlzLT5fYm9keSAgICAgICAgICAgPSBudWxsOwoKICAgICAgICAkdGhpcy0+X3VzZXIgPSBudWxsOwogICAgICAgICR0aGlzLT5fcGFzcyA9IG51bGw7CgogICAgICAgICR0aGlzLT5fcHJveHlfaG9zdCA9IG51bGw7CiAgICAgICAgJHRoaXMtPl9wcm94eV9wb3J0ID0gbnVsbDsKICAgICAgICAkdGhpcy0+X3Byb3h5X3VzZXIgPSBudWxsOwogICAgICAgICR0aGlzLT5fcHJveHlfcGFzcyA9IG51bGw7CgogICAgICAgICR0aGlzLT5fYWxsb3dSZWRpcmVjdHMgPSBmYWxzZTsKICAgICAgICAkdGhpcy0+X21heFJlZGlyZWN0cyAgID0gMzsKICAgICAgICAkdGhpcy0+X3JlZGlyZWN0cyAgICAgID0gMDsKCiAgICAgICAgJHRoaXMtPl90aW1lb3V0ICA9IG51bGw7CiAgICAgICAgJHRoaXMtPl9yZXNwb25zZSA9IG51bGw7CgogICAgICAgIGZvcmVhY2ggKCRwYXJhbXMgYXMgJGtleSA9PiAkdmFsdWUpIHsKICAgICAgICAgICAgJHRoaXMtPnsnXycgLiAka2V5fSA9ICR2YWx1ZTsKICAgICAgICB9CgogICAgICAgIGlmICghZW1wdHkoJHVybCkpIHsKICAgICAgICAgICAgJHRoaXMtPnNldFVSTCgkdXJsKTsKICAgICAgICB9CgogICAgICAgIC8vIERlZmF1bHQgdXNlcmFnZW50CiAgICAgICAgJHRoaXMtPmFkZEhlYWRlcignVXNlci1BZ2VudCcsICdQRUFSIEhUVFBfUmVxdWVzdCBjbGFzcyAoIGh0dHA6Ly9wZWFyLnBocC5uZXQvICknKTsKCiAgICAgICAgLy8gV2UgZG9uJ3QgZG8ga2VlcC1hbGl2ZXMgYnkgZGVmYXVsdAogICAgICAgICR0aGlzLT5hZGRIZWFkZXIoJ0Nvbm5lY3Rpb24nLCAnY2xvc2UnKTsKCiAgICAgICAgLy8gQmFzaWMgYXV0aGVudGljYXRpb24KICAgICAgICBpZiAoIWVtcHR5KCR0aGlzLT5fdXNlcikpIHsKICAgICAgICAgICAgJHRoaXMtPmFkZEhlYWRlcignQXV0aG9yaXphdGlvbicsICdCYXNpYyAnIC4gYmFzZTY0X2VuY29kZSgkdGhpcy0+X3VzZXIgLiAnOicgLiAkdGhpcy0+X3Bhc3MpKTsKICAgICAgICB9CgogICAgICAgIC8vIFByb3h5IGF1dGhlbnRpY2F0aW9uIChzZWUgYnVnICM1OTEzKQogICAgICAgIGlmICghZW1wdHkoJHRoaXMtPl9wcm94eV91c2VyKSkgewogICAgICAgICAgICAkdGhpcy0+YWRkSGVhZGVyKCdQcm94eS1BdXRob3JpemF0aW9uJywgJ0Jhc2ljICcgLiBiYXNlNjRfZW5jb2RlKCR0aGlzLT5fcHJveHlfdXNlciAuICc6JyAuICR0aGlzLT5fcHJveHlfcGFzcykpOwogICAgICAgIH0KCiAgICAgICAgLy8gVXNlIGd6aXAgZW5jb2RpbmcgaWYgcG9zc2libGUKICAgICAgICBpZiAoSFRUUF9SRVFVRVNUX0hUVFBfVkVSXzFfMSA9PSAkdGhpcy0+X2h0dHAgJiYgZXh0ZW5zaW9uX2xvYWRlZCgnemxpYicpKSB7CiAgICAgICAgICAgICR0aGlzLT5hZGRIZWFkZXIoJ0FjY2VwdC1FbmNvZGluZycsICdnemlwJyk7CiAgICAgICAgfQogICAgfQoKICAgIC8qKgogICAgKiBHZW5lcmF0ZXMgYSBIb3N0IGhlYWRlciBmb3IgSFRUUC8xLjEgcmVxdWVzdHMKICAgICoKICAgICogQGFjY2VzcyBwcml2YXRlCiAgICAqIEByZXR1cm4gc3RyaW5nCiAgICAqLwogICAgZnVuY3Rpb24gX2dlbmVyYXRlSG9zdEhlYWRlcigpCiAgICB7CiAgICAgICAgaWYgKCR0aGlzLT5fdXJsLT5wb3J0ICE9IDgwIEFORCBzdHJjYXNlY21wKCR0aGlzLT5fdXJsLT5wcm90b2NvbCwgJ2h0dHAnKSA9PSAwKSB7CiAgICAgICAgICAgICRob3N0ID0gJHRoaXMtPl91cmwtPmhvc3QgLiAnOicgLiAkdGhpcy0+X3VybC0+cG9ydDsKCiAgICAgICAgfSBlbHNlaWYgKCR0aGlzLT5fdXJsLT5wb3J0ICE9IDQ0MyBBTkQgc3RyY2FzZWNtcCgkdGhpcy0+X3VybC0+cHJvdG9jb2wsICdodHRwcycpID09IDApIHsKICAgICAgICAgICAgJGhvc3QgPSAkdGhpcy0+X3VybC0+aG9zdCAuICc6JyAuICR0aGlzLT5fdXJsLT5wb3J0OwoKICAgICAgICB9IGVsc2VpZiAoJHRoaXMtPl91cmwtPnBvcnQgPT0gNDQzIEFORCBzdHJjYXNlY21wKCR0aGlzLT5fdXJsLT5wcm90b2NvbCwgJ2h0dHBzJykgPT0gMCBBTkQgc3RycG9zKCR0aGlzLT5fdXJsLT51cmwsICc6NDQzJykgIT09IGZhbHNlKSB7CiAgICAgICAgICAgICRob3N0ID0gJHRoaXMtPl91cmwtPmhvc3QgLiAnOicgLiAkdGhpcy0+X3VybC0+cG9ydDsKCiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgJGhvc3QgPSAkdGhpcy0+X3VybC0+aG9zdDsKICAgICAgICB9CgogICAgICAgIHJldHVybiAkaG9zdDsKICAgIH0KCiAgICAvKioKICAgICogUmVzZXRzIHRoZSBvYmplY3QgdG8gaXRzIGluaXRpYWwgc3RhdGUgKERFUFJFQ0FURUQpLgogICAgKiBUYWtlcyB0aGUgc2FtZSBwYXJhbWV0ZXJzIGFzIHRoZSBjb25zdHJ1Y3Rvci4KICAgICoKICAgICogQHBhcmFtICBzdHJpbmcgJHVybCAgICBUaGUgdXJsIHRvIGJlIHJlcXVlc3RlZAogICAgKiBAcGFyYW0gIGFycmF5ICAkcGFyYW1zIEFzc29jaWF0aXZlIGFycmF5IG9mIHBhcmFtZXRlcnMKICAgICogICAgICAgICAgICAgICAgICAgICAgICAoc2VlIGNvbnN0cnVjdG9yIGZvciBkZXRhaWxzKQogICAgKiBAYWNjZXNzIHB1YmxpYwogICAgKiBAZGVwcmVjYXRlZCBkZXByZWNhdGVkIHNpbmNlIDEuMiwgY2FsbCB0aGUgY29uc3RydWN0b3IgaWYgdGhpcyBpcyBuZWNlc3NhcnkKICAgICovCiAgICBmdW5jdGlvbiByZXNldCgkdXJsLCAkcGFyYW1zID0gYXJyYXkoKSkKICAgIHsKICAgICAgICAkdGhpcy0+SFRUUF9SZXF1ZXN0KCR1cmwsICRwYXJhbXMpOwogICAgfQoKICAgIC8qKgogICAgKiBTZXRzIHRoZSBVUkwgdG8gYmUgcmVxdWVzdGVkCiAgICAqCiAgICAqIEBwYXJhbSAgc3RyaW5nIFRoZSB1cmwgdG8gYmUgcmVxdWVzdGVkCiAgICAqIEBhY2Nlc3MgcHVibGljCiAgICAqLwogICAgZnVuY3Rpb24gc2V0VVJMKCR1cmwpCiAgICB7CiAgICAgICAgJHRoaXMtPl91cmwgPSAmbmV3IE5ldF9VUkwoJHVybCwgJHRoaXMtPl91c2VCcmFja2V0cyk7CgogICAgICAgIGlmICghZW1wdHkoJHRoaXMtPl91cmwtPnVzZXIpIHx8ICFlbXB0eSgkdGhpcy0+X3VybC0+cGFzcykpIHsKICAgICAgICAgICAgJHRoaXMtPnNldEJhc2ljQXV0aCgkdGhpcy0+X3VybC0+dXNlciwgJHRoaXMtPl91cmwtPnBhc3MpOwogICAgICAgIH0KCiAgICAgICAgaWYgKEhUVFBfUkVRVUVTVF9IVFRQX1ZFUl8xXzEgPT0gJHRoaXMtPl9odHRwKSB7CiAgICAgICAgICAgICR0aGlzLT5hZGRIZWFkZXIoJ0hvc3QnLCAkdGhpcy0+X2dlbmVyYXRlSG9zdEhlYWRlcigpKTsKICAgICAgICB9CgogICAgICAgIC8vIHNldCAnLycgaW5zdGVhZCBvZiBlbXB0eSBwYXRoIHJhdGhlciB0aGFuIGNoZWNrIGxhdGVyIChzZWUgYnVnICM4NjYyKQogICAgICAgIGlmIChlbXB0eSgkdGhpcy0+X3VybC0+cGF0aCkpIHsKICAgICAgICAgICAgJHRoaXMtPl91cmwtPnBhdGggPSAnLyc7CiAgICAgICAgfQogICAgfQoKICAgLyoqCiAgICAqIFJldHVybnMgdGhlIGN1cnJlbnQgcmVxdWVzdCBVUkwKICAgICoKICAgICogQHJldHVybiAgIHN0cmluZyAgQ3VycmVudCByZXF1ZXN0IFVSTAogICAgKiBAYWNjZXNzICAgcHVibGljCiAgICAqLwogICAgZnVuY3Rpb24gZ2V0VXJsKCkKICAgIHsKICAgICAgICByZXR1cm4gZW1wdHkoJHRoaXMtPl91cmwpPyAnJzogJHRoaXMtPl91cmwtPmdldFVybCgpOwogICAgfQoKICAgIC8qKgogICAgKiBTZXRzIGEgcHJveHkgdG8gYmUgdXNlZAogICAgKgogICAgKiBAcGFyYW0gc3RyaW5nICAgICBQcm94eSBob3N0CiAgICAqIEBwYXJhbSBpbnQgICAgICAgIFByb3h5IHBvcnQKICAgICogQHBhcmFtIHN0cmluZyAgICAgUHJveHkgdXNlcm5hbWUKICAgICogQHBhcmFtIHN0cmluZyAgICAgUHJveHkgcGFzc3dvcmQKICAgICogQGFjY2VzcyBwdWJsaWMKICAgICovCiAgICBmdW5jdGlvbiBzZXRQcm94eSgkaG9zdCwgJHBvcnQgPSA4MDgwLCAkdXNlciA9IG51bGwsICRwYXNzID0gbnVsbCkKICAgIHsKICAgICAgICAkdGhpcy0+X3Byb3h5X2hvc3QgPSAkaG9zdDsKICAgICAgICAkdGhpcy0+X3Byb3h5X3BvcnQgPSAkcG9ydDsKICAgICAgICAkdGhpcy0+X3Byb3h5X3VzZXIgPSAkdXNlcjsKICAgICAgICAkdGhpcy0+X3Byb3h5X3Bhc3MgPSAkcGFzczsKCiAgICAgICAgaWYgKCFlbXB0eSgkdXNlcikpIHsKICAgICAgICAgICAgJHRoaXMtPmFkZEhlYWRlcignUHJveHktQXV0aG9yaXphdGlvbicsICdCYXNpYyAnIC4gYmFzZTY0X2VuY29kZSgkdXNlciAuICc6JyAuICRwYXNzKSk7CiAgICAgICAgfQogICAgfQoKICAgIC8qKgogICAgKiBTZXRzIGJhc2ljIGF1dGhlbnRpY2F0aW9uIHBhcmFtZXRlcnMKICAgICoKICAgICogQHBhcmFtIHN0cmluZyAgICAgVXNlcm5hbWUKICAgICogQHBhcmFtIHN0cmluZyAgICAgUGFzc3dvcmQKICAgICovCiAgICBmdW5jdGlvbiBzZXRCYXNpY0F1dGgoJHVzZXIsICRwYXNzKQogICAgewogICAgICAgICR0aGlzLT5fdXNlciA9ICR1c2VyOwogICAgICAgICR0aGlzLT5fcGFzcyA9ICRwYXNzOwoKICAgICAgICAkdGhpcy0+YWRkSGVhZGVyKCdBdXRob3JpemF0aW9uJywgJ0Jhc2ljICcgLiBiYXNlNjRfZW5jb2RlKCR1c2VyIC4gJzonIC4gJHBhc3MpKTsKICAgIH0KCiAgICAvKioKICAgICogU2V0cyB0aGUgbWV0aG9kIHRvIGJlIHVzZWQsIEdFVCwgUE9TVCBldGMuCiAgICAqCiAgICAqIEBwYXJhbSBzdHJpbmcgICAgIE1ldGhvZCB0byB1c2UuIFVzZSB0aGUgZGVmaW5lZCBjb25zdGFudHMgZm9yIHRoaXMKICAgICogQGFjY2VzcyBwdWJsaWMKICAgICovCiAgICBmdW5jdGlvbiBzZXRNZXRob2QoJG1ldGhvZCkKICAgIHsKICAgICAgICAkdGhpcy0+X21ldGhvZCA9ICRtZXRob2Q7CiAgICB9CgogICAgLyoqCiAgICAqIFNldHMgdGhlIEhUVFAgdmVyc2lvbiB0byB1c2UsIDEuMCBvciAxLjEKICAgICoKICAgICogQHBhcmFtIHN0cmluZyAgICAgVmVyc2lvbiB0byB1c2UuIFVzZSB0aGUgZGVmaW5lZCBjb25zdGFudHMgZm9yIHRoaXMKICAgICogQGFjY2VzcyBwdWJsaWMKICAgICovCiAgICBmdW5jdGlvbiBzZXRIdHRwVmVyKCRodHRwKQogICAgewogICAgICAgICR0aGlzLT5faHR0cCA9ICRodHRwOwogICAgfQoKICAgIC8qKgogICAgKiBBZGRzIGEgcmVxdWVzdCBoZWFkZXIKICAgICoKICAgICogQHBhcmFtIHN0cmluZyAgICAgSGVhZGVyIG5hbWUKICAgICogQHBhcmFtIHN0cmluZyAgICAgSGVhZGVyIHZhbHVlCiAgICAqIEBhY2Nlc3MgcHVibGljCiAgICAqLwogICAgZnVuY3Rpb24gYWRkSGVhZGVyKCRuYW1lLCAkdmFsdWUpCiAgICB7CiAgICAgICAgJHRoaXMtPl9yZXF1ZXN0SGVhZGVyc1tzdHJ0b2xvd2VyKCRuYW1lKV0gPSAkdmFsdWU7CiAgICB9CgogICAgLyoqCiAgICAqIFJlbW92ZXMgYSByZXF1ZXN0IGhlYWRlcgogICAgKgogICAgKiBAcGFyYW0gc3RyaW5nICAgICBIZWFkZXIgbmFtZSB0byByZW1vdmUKICAgICogQGFjY2VzcyBwdWJsaWMKICAgICovCiAgICBmdW5jdGlvbiByZW1vdmVIZWFkZXIoJG5hbWUpCiAgICB7CiAgICAgICAgaWYgKGlzc2V0KCR0aGlzLT5fcmVxdWVzdEhlYWRlcnNbc3RydG9sb3dlcigkbmFtZSldKSkgewogICAgICAgICAgICB1bnNldCgkdGhpcy0+X3JlcXVlc3RIZWFkZXJzW3N0cnRvbG93ZXIoJG5hbWUpXSk7CiAgICAgICAgfQogICAgfQoKICAgIC8qKgogICAgKiBBZGRzIGEgcXVlcnlzdHJpbmcgcGFyYW1ldGVyCiAgICAqCiAgICAqIEBwYXJhbSBzdHJpbmcgICAgIFF1ZXJ5c3RyaW5nIHBhcmFtZXRlciBuYW1lCiAgICAqIEBwYXJhbSBzdHJpbmcgICAgIFF1ZXJ5c3RyaW5nIHBhcmFtZXRlciB2YWx1ZQogICAgKiBAcGFyYW0gYm9vbCAgICAgICBXaGV0aGVyIHRoZSB2YWx1ZSBpcyBhbHJlYWR5IHVybGVuY29kZWQgb3Igbm90LCBkZWZhdWx0ID0gbm90CiAgICAqIEBhY2Nlc3MgcHVibGljCiAgICAqLwogICAgZnVuY3Rpb24gYWRkUXVlcnlTdHJpbmcoJG5hbWUsICR2YWx1ZSwgJHByZWVuY29kZWQgPSBmYWxzZSkKICAgIHsKICAgICAgICAkdGhpcy0+X3VybC0+YWRkUXVlcnlTdHJpbmcoJG5hbWUsICR2YWx1ZSwgJHByZWVuY29kZWQpOwogICAgfQoKICAgIC8qKgogICAgKiBTZXRzIHRoZSBxdWVyeXN0cmluZyB0byBsaXRlcmFsbHkgd2hhdCB5b3Ugc3VwcGx5CiAgICAqCiAgICAqIEBwYXJhbSBzdHJpbmcgICAgIFRoZSBxdWVyeXN0cmluZyBkYXRhLiBTaG91bGQgYmUgb2YgdGhlIGZvcm1hdCBmb289YmFyJng9eSBldGMKICAgICogQHBhcmFtIGJvb2wgICAgICAgV2hldGhlciBkYXRhIGlzIGFscmVhZHkgdXJsZW5jb2RlZCBvciBub3QsIGRlZmF1bHQgPSBhbHJlYWR5IGVuY29kZWQKICAgICogQGFjY2VzcyBwdWJsaWMKICAgICovCiAgICBmdW5jdGlvbiBhZGRSYXdRdWVyeVN0cmluZygkcXVlcnlzdHJpbmcsICRwcmVlbmNvZGVkID0gdHJ1ZSkKICAgIHsKICAgICAgICAkdGhpcy0+X3VybC0+YWRkUmF3UXVlcnlTdHJpbmcoJHF1ZXJ5c3RyaW5nLCAkcHJlZW5jb2RlZCk7CiAgICB9CgogICAgLyoqCiAgICAqIEFkZHMgcG9zdGRhdGEgaXRlbXMKICAgICoKICAgICogQHBhcmFtIHN0cmluZyAgICAgUG9zdCBkYXRhIG5hbWUKICAgICogQHBhcmFtIHN0cmluZyAgICAgUG9zdCBkYXRhIHZhbHVlCiAgICAqIEBwYXJhbSBib29sICAgICAgIFdoZXRoZXIgZGF0YSBpcyBhbHJlYWR5IHVybGVuY29kZWQgb3Igbm90LCBkZWZhdWx0ID0gbm90CiAgICAqIEBhY2Nlc3MgcHVibGljCiAgICAqLwogICAgZnVuY3Rpb24gYWRkUG9zdERhdGEoJG5hbWUsICR2YWx1ZSwgJHByZWVuY29kZWQgPSBmYWxzZSkKICAgIHsKICAgICAgICBpZiAoJHByZWVuY29kZWQpIHsKICAgICAgICAgICAgJHRoaXMtPl9wb3N0RGF0YVskbmFtZV0gPSAkdmFsdWU7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgJHRoaXMtPl9wb3N0RGF0YVskbmFtZV0gPSAkdGhpcy0+X2FycmF5TWFwUmVjdXJzaXZlKCd1cmxlbmNvZGUnLCAkdmFsdWUpOwogICAgICAgIH0KICAgIH0KCiAgIC8qKgogICAgKiBSZWN1cnNpdmVseSBhcHBsaWVzIHRoZSBjYWxsYmFjayBmdW5jdGlvbiB0byB0aGUgdmFsdWUKICAgICoKICAgICogQHBhcmFtICAgIG1peGVkICAgQ2FsbGJhY2sgZnVuY3Rpb24KICAgICogQHBhcmFtICAgIG1peGVkICAgVmFsdWUgdG8gcHJvY2VzcwogICAgKiBAYWNjZXNzICAgcHJpdmF0ZQogICAgKiBAcmV0dXJuICAgbWl4ZWQgICBQcm9jZXNzZWQgdmFsdWUKICAgICovCiAgICBmdW5jdGlvbiBfYXJyYXlNYXBSZWN1cnNpdmUoJGNhbGxiYWNrLCAkdmFsdWUpCiAgICB7CiAgICAgICAgaWYgKCFpc19hcnJheSgkdmFsdWUpKSB7CiAgICAgICAgICAgIHJldHVybiBjYWxsX3VzZXJfZnVuYygkY2FsbGJhY2ssICR2YWx1ZSk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgJG1hcCA9IGFycmF5KCk7CiAgICAgICAgICAgIGZvcmVhY2ggKCR2YWx1ZSBhcyAkayA9PiAkdikgewogICAgICAgICAgICAgICAgJG1hcFska10gPSAkdGhpcy0+X2FycmF5TWFwUmVjdXJzaXZlKCRjYWxsYmFjaywgJHYpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHJldHVybiAkbWFwOwogICAgICAgIH0KICAgIH0KCiAgIC8qKgogICAgKiBBZGRzIGEgZmlsZSB0byBmb3JtLWJhc2VkIGZpbGUgdXBsb2FkCiAgICAqCiAgICAqIFVzZWQgdG8gZW11bGF0ZSBmaWxlIHVwbG9hZCB2aWEgYSBIVE1MIGZvcm0uIFRoZSBtZXRob2QgYWxzbyBzZXRzCiAgICAqIENvbnRlbnQtVHlwZSBvZiBIVFRQIHJlcXVlc3QgdG8gJ211bHRpcGFydC9mb3JtLWRhdGEnLgogICAgKgogICAgKiBJZiB5b3UganVzdCB3YW50IHRvIHNlbmQgdGhlIGNvbnRlbnRzIG9mIGEgZmlsZSBhcyB0aGUgYm9keSBvZiBIVFRQCiAgICAqIHJlcXVlc3QgeW91IHNob3VsZCB1c2Ugc2V0Qm9keSgpIG1ldGhvZC4KICAgICoKICAgICogQGFjY2VzcyBwdWJsaWMKICAgICogQHBhcmFtICBzdHJpbmcgICAgbmFtZSBvZiBmaWxlLXVwbG9hZCBmaWVsZAogICAgKiBAcGFyYW0gIG1peGVkICAgICBmaWxlIG5hbWUocykKICAgICogQHBhcmFtICBtaXhlZCAgICAgY29udGVudC10eXBlKHMpIG9mIGZpbGUocykgYmVpbmcgdXBsb2FkZWQKICAgICogQHJldHVybiBib29sICAgICAgdHJ1ZSBvbiBzdWNjZXNzCiAgICAqIEB0aHJvd3MgUEVBUl9FcnJvcgogICAgKi8KICAgIGZ1bmN0aW9uIGFkZEZpbGUoJGlucHV0TmFtZSwgJGZpbGVOYW1lLCAkY29udGVudFR5cGUgPSAnYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtJykKICAgIHsKICAgICAgICBpZiAoIWlzX2FycmF5KCRmaWxlTmFtZSkgJiYgIWlzX3JlYWRhYmxlKCRmaWxlTmFtZSkpIHsKICAgICAgICAgICAgcmV0dXJuIFBFQVI6OnJhaXNlRXJyb3IoIkZpbGUgJ3skZmlsZU5hbWV9JyBpcyBub3QgcmVhZGFibGUiLCBIVFRQX1JFUVVFU1RfRVJST1JfRklMRSk7CiAgICAgICAgfSBlbHNlaWYgKGlzX2FycmF5KCRmaWxlTmFtZSkpIHsKICAgICAgICAgICAgZm9yZWFjaCAoJGZpbGVOYW1lIGFzICRuYW1lKSB7CiAgICAgICAgICAgICAgICBpZiAoIWlzX3JlYWRhYmxlKCRuYW1lKSkgewogICAgICAgICAgICAgICAgICAgIHJldHVybiBQRUFSOjpyYWlzZUVycm9yKCJGaWxlICd7JG5hbWV9JyBpcyBub3QgcmVhZGFibGUiLCBIVFRQX1JFUVVFU1RfRVJST1JfRklMRSk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgJHRoaXMtPmFkZEhlYWRlcignQ29udGVudC1UeXBlJywgJ211bHRpcGFydC9mb3JtLWRhdGEnKTsKICAgICAgICAkdGhpcy0+X3Bvc3RGaWxlc1skaW5wdXROYW1lXSA9IGFycmF5KAogICAgICAgICAgICAnbmFtZScgPT4gJGZpbGVOYW1lLAogICAgICAgICAgICAndHlwZScgPT4gJGNvbnRlbnRUeXBlCiAgICAgICAgKTsKICAgICAgICByZXR1cm4gdHJ1ZTsKICAgIH0KCiAgICAvKioKICAgICogQWRkcyByYXcgcG9zdGRhdGEgKERFUFJFQ0FURUQpCiAgICAqCiAgICAqIEBwYXJhbSBzdHJpbmcgICAgIFRoZSBkYXRhCiAgICAqIEBwYXJhbSBib29sICAgICAgIFdoZXRoZXIgZGF0YSBpcyBwcmVlbmNvZGVkIG9yIG5vdCwgZGVmYXVsdCA9IGFscmVhZHkgZW5jb2RlZAogICAgKiBAYWNjZXNzIHB1YmxpYwogICAgKiBAZGVwcmVjYXRlZCAgICAgICBkZXByZWNhdGVkIHNpbmNlIDEuMy4wLCBtZXRob2Qgc2V0Qm9keSgpIHNob3VsZCBiZSB1c2VkIGluc3RlYWQKICAgICovCiAgICBmdW5jdGlvbiBhZGRSYXdQb3N0RGF0YSgkcG9zdGRhdGEsICRwcmVlbmNvZGVkID0gdHJ1ZSkKICAgIHsKICAgICAgICAkdGhpcy0+X2JvZHkgPSAkcHJlZW5jb2RlZCA/ICRwb3N0ZGF0YSA6IHVybGVuY29kZSgkcG9zdGRhdGEpOwogICAgfQoKICAgLyoqCiAgICAqIFNldHMgdGhlIHJlcXVlc3QgYm9keSAoZm9yIFBPU1QsIFBVVCBhbmQgc2ltaWxhciByZXF1ZXN0cykKICAgICoKICAgICogQHBhcmFtICAgIHN0cmluZyAgUmVxdWVzdCBib2R5CiAgICAqIEBhY2Nlc3MgICBwdWJsaWMKICAgICovCiAgICBmdW5jdGlvbiBzZXRCb2R5KCRib2R5KQogICAgewogICAgICAgICR0aGlzLT5fYm9keSA9ICRib2R5OwogICAgfQoKICAgIC8qKgogICAgKiBDbGVhcnMgYW55IHBvc3RkYXRhIHRoYXQgaGFzIGJlZW4gYWRkZWQgKERFUFJFQ0FURUQpLgogICAgKgogICAgKiBVc2VmdWwgZm9yIG11bHRpcGxlIHJlcXVlc3Qgc2NlbmFyaW9zLgogICAgKgogICAgKiBAYWNjZXNzIHB1YmxpYwogICAgKiBAZGVwcmVjYXRlZCBkZXByZWNhdGVkIHNpbmNlIDEuMgogICAgKi8KICAgIGZ1bmN0aW9uIGNsZWFyUG9zdERhdGEoKQogICAgewogICAgICAgICR0aGlzLT5fcG9zdERhdGEgPSBudWxsOwogICAgfQoKICAgIC8qKgogICAgKiBBcHBlbmRzIGEgY29va2llIHRvICJDb29raWU6IiBoZWFkZXIKICAgICoKICAgICogQHBhcmFtIHN0cmluZyAkbmFtZSBjb29raWUgbmFtZQogICAgKiBAcGFyYW0gc3RyaW5nICR2YWx1ZSBjb29raWUgdmFsdWUKICAgICogQGFjY2VzcyBwdWJsaWMKICAgICovCiAgICBmdW5jdGlvbiBhZGRDb29raWUoJG5hbWUsICR2YWx1ZSkKICAgIHsKICAgICAgICAkY29va2llcyA9IGlzc2V0KCR0aGlzLT5fcmVxdWVzdEhlYWRlcnNbJ2Nvb2tpZSddKSA/ICR0aGlzLT5fcmVxdWVzdEhlYWRlcnNbJ2Nvb2tpZSddLiAnOyAnIDogJyc7CiAgICAgICAgJHRoaXMtPmFkZEhlYWRlcignQ29va2llJywgJGNvb2tpZXMgLiAkbmFtZSAuICc9JyAuICR2YWx1ZSk7CiAgICB9CgogICAgLyoqCiAgICAqIENsZWFycyBhbnkgY29va2llcyB0aGF0IGhhdmUgYmVlbiBhZGRlZCAoREVQUkVDQVRFRCkuCiAgICAqCiAgICAqIFVzZWZ1bCBmb3IgbXVsdGlwbGUgcmVxdWVzdCBzY2VuYXJpb3MKICAgICoKICAgICogQGFjY2VzcyBwdWJsaWMKICAgICogQGRlcHJlY2F0ZWQgZGVwcmVjYXRlZCBzaW5jZSAxLjIKICAgICovCiAgICBmdW5jdGlvbiBjbGVhckNvb2tpZXMoKQogICAgewogICAgICAgICR0aGlzLT5yZW1vdmVIZWFkZXIoJ0Nvb2tpZScpOwogICAgfQoKICAgIC8qKgogICAgKiBTZW5kcyB0aGUgcmVxdWVzdAogICAgKgogICAgKiBAYWNjZXNzIHB1YmxpYwogICAgKiBAcGFyYW0gIGJvb2wgICBXaGV0aGVyIHRvIHN0b3JlIHJlc3BvbnNlIGJvZHkgaW4gUmVzcG9uc2Ugb2JqZWN0IHByb3BlcnR5LAogICAgKiAgICAgICAgICAgICAgICBzZXQgdGhpcyB0byBmYWxzZSBpZiBkb3dubG9hZGluZyBhIExBUkdFIGZpbGUgYW5kIHVzaW5nIGEgTGlzdGVuZXIKICAgICogQHJldHVybiBtaXhlZCAgUEVBUiBlcnJvciBvbiBlcnJvciwgdHJ1ZSBvdGhlcndpc2UKICAgICovCiAgICBmdW5jdGlvbiBzZW5kUmVxdWVzdCgkc2F2ZUJvZHkgPSB0cnVlKQogICAgewogICAgICAgIGlmICghaXNfYSgkdGhpcy0+X3VybCwgJ05ldF9VUkwnKSkgewogICAgICAgICAgICByZXR1cm4gUEVBUjo6cmFpc2VFcnJvcignTm8gVVJMIGdpdmVuJywgSFRUUF9SRVFVRVNUX0VSUk9SX1VSTCk7CiAgICAgICAgfQoKICAgICAgICAkaG9zdCA9IGlzc2V0KCR0aGlzLT5fcHJveHlfaG9zdCkgPyAkdGhpcy0+X3Byb3h5X2hvc3QgOiAkdGhpcy0+X3VybC0+aG9zdDsKICAgICAgICAkcG9ydCA9IGlzc2V0KCR0aGlzLT5fcHJveHlfcG9ydCkgPyAkdGhpcy0+X3Byb3h5X3BvcnQgOiAkdGhpcy0+X3VybC0+cG9ydDsKCiAgICAgICAgaWYgKHN0cmNhc2VjbXAoJHRoaXMtPl91cmwtPnByb3RvY29sLCAnaHR0cHMnKSA9PSAwKSB7CiAgICAgICAgICAgIC8vIEJ1ZyAjMTQxMjcsIGRvbid0IHRyeSBjb25uZWN0aW5nIHRvIEhUVFBTIHNpdGVzIHdpdGhvdXQgT3BlblNTTAogICAgICAgICAgICBpZiAodmVyc2lvbl9jb21wYXJlKFBIUF9WRVJTSU9OLCAnNC4zLjAnLCAnPCcpIHx8ICFleHRlbnNpb25fbG9hZGVkKCdvcGVuc3NsJykpIHsKICAgICAgICAgICAgICAgIHJldHVybiBQRUFSOjpyYWlzZUVycm9yKCdOZWVkIFBIUCA0LjMuMCBvciBsYXRlciB3aXRoIE9wZW5TU0wgc3VwcG9ydCBmb3IgaHR0cHM6Ly8gcmVxdWVzdHMnLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgSFRUUF9SRVFVRVNUX0VSUk9SX1VSTCk7CiAgICAgICAgICAgIH0gZWxzZWlmIChpc3NldCgkdGhpcy0+X3Byb3h5X2hvc3QpKSB7CiAgICAgICAgICAgICAgICByZXR1cm4gUEVBUjo6cmFpc2VFcnJvcignSFRUUFMgcHJveGllcyBhcmUgbm90IHN1cHBvcnRlZCcsIEhUVFBfUkVRVUVTVF9FUlJPUl9QUk9YWSk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgJGhvc3QgPSAnc3NsOi8vJyAuICRob3N0OwogICAgICAgIH0KCiAgICAgICAgLy8gbWFnaWMgcXVvdGVzIG1heSBmdWNrIHVwIGZpbGUgdXBsb2FkcyBhbmQgY2h1bmtlZCByZXNwb25zZSBwcm9jZXNzaW5nCiAgICAgICAgJG1hZ2ljUXVvdGVzID0gaW5pX2dldCgnbWFnaWNfcXVvdGVzX3J1bnRpbWUnKTsKICAgICAgICBpbmlfc2V0KCdtYWdpY19xdW90ZXNfcnVudGltZScsIGZhbHNlKTsKCiAgICAgICAgLy8gUkZDIDIwNjgsIHNlY3Rpb24gMTkuNy4xOiBBIGNsaWVudCBNVVNUIE5PVCBzZW5kIHRoZSBLZWVwLUFsaXZlCiAgICAgICAgLy8gY29ubmVjdGlvbiB0b2tlbiB0byBhIHByb3h5IHNlcnZlci4uLgogICAgICAgIGlmIChpc3NldCgkdGhpcy0+X3Byb3h5X2hvc3QpICYmICFlbXB0eSgkdGhpcy0+X3JlcXVlc3RIZWFkZXJzWydjb25uZWN0aW9uJ10pICYmCiAgICAgICAgICAgICdLZWVwLUFsaXZlJyA9PSAkdGhpcy0+X3JlcXVlc3RIZWFkZXJzWydjb25uZWN0aW9uJ10pCiAgICAgICAgewogICAgICAgICAgICAkdGhpcy0+cmVtb3ZlSGVhZGVyKCdjb25uZWN0aW9uJyk7CiAgICAgICAgfQoKICAgICAgICAka2VlcEFsaXZlID0gKEhUVFBfUkVRVUVTVF9IVFRQX1ZFUl8xXzEgPT0gJHRoaXMtPl9odHRwICYmIGVtcHR5KCR0aGlzLT5fcmVxdWVzdEhlYWRlcnNbJ2Nvbm5lY3Rpb24nXSkpIHx8CiAgICAgICAgICAgICAgICAgICAgICghZW1wdHkoJHRoaXMtPl9yZXF1ZXN0SGVhZGVyc1snY29ubmVjdGlvbiddKSAmJiAnS2VlcC1BbGl2ZScgPT0gJHRoaXMtPl9yZXF1ZXN0SGVhZGVyc1snY29ubmVjdGlvbiddKTsKICAgICAgICAkc29ja2V0cyAgID0gJlBFQVI6OmdldFN0YXRpY1Byb3BlcnR5KCdIVFRQX1JlcXVlc3QnLCAnc29ja2V0cycpOwogICAgICAgICRzb2NrS2V5ICAgPSAkaG9zdCAuICc6JyAuICRwb3J0OwogICAgICAgIHVuc2V0KCR0aGlzLT5fc29jayk7CgogICAgICAgIC8vIFRoZXJlIGlzIGEgY29ubmVjdGVkIHNvY2tldCBpbiB0aGUgInN0YXRpYyIgcHJvcGVydHk/CiAgICAgICAgaWYgKCRrZWVwQWxpdmUgJiYgIWVtcHR5KCRzb2NrZXRzWyRzb2NrS2V5XSkgJiYKICAgICAgICAgICAgIWVtcHR5KCRzb2NrZXRzWyRzb2NrS2V5XS0+ZnApKQogICAgICAgIHsKICAgICAgICAgICAgJHRoaXMtPl9zb2NrID0mICRzb2NrZXRzWyRzb2NrS2V5XTsKICAgICAgICAgICAgJGVyciA9IG51bGw7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgJHRoaXMtPl9ub3RpZnkoJ2Nvbm5lY3QnKTsKICAgICAgICAgICAgJHRoaXMtPl9zb2NrID0mIG5ldyBOZXRfU29ja2V0KCk7CiAgICAgICAgICAgICRlcnIgPSAkdGhpcy0+X3NvY2stPmNvbm5lY3QoJGhvc3QsICRwb3J0LCBudWxsLCAkdGhpcy0+X3RpbWVvdXQsICR0aGlzLT5fc29ja2V0T3B0aW9ucyk7CiAgICAgICAgfQogICAgICAgIFBFQVI6OmlzRXJyb3IoJGVycikgb3IgJGVyciA9ICR0aGlzLT5fc29jay0+d3JpdGUoJHRoaXMtPl9idWlsZFJlcXVlc3QoKSk7CgogICAgICAgIGlmICghUEVBUjo6aXNFcnJvcigkZXJyKSkgewogICAgICAgICAgICBpZiAoIWVtcHR5KCR0aGlzLT5fcmVhZFRpbWVvdXQpKSB7CiAgICAgICAgICAgICAgICAkdGhpcy0+X3NvY2stPnNldFRpbWVvdXQoJHRoaXMtPl9yZWFkVGltZW91dFswXSwgJHRoaXMtPl9yZWFkVGltZW91dFsxXSk7CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgICR0aGlzLT5fbm90aWZ5KCdzZW50UmVxdWVzdCcpOwoKICAgICAgICAgICAgLy8gUmVhZCB0aGUgcmVzcG9uc2UKICAgICAgICAgICAgJHRoaXMtPl9yZXNwb25zZSA9ICZuZXcgSFRUUF9SZXNwb25zZSgkdGhpcy0+X3NvY2ssICR0aGlzLT5fbGlzdGVuZXJzKTsKICAgICAgICAgICAgJGVyciA9ICR0aGlzLT5fcmVzcG9uc2UtPnByb2Nlc3MoCiAgICAgICAgICAgICAgICAkdGhpcy0+X3NhdmVCb2R5ICYmICRzYXZlQm9keSwKICAgICAgICAgICAgICAgIEhUVFBfUkVRVUVTVF9NRVRIT0RfSEVBRCAhPSAkdGhpcy0+X21ldGhvZAogICAgICAgICAgICApOwoKICAgICAgICAgICAgaWYgKCRrZWVwQWxpdmUpIHsKICAgICAgICAgICAgICAgICRrZWVwQWxpdmUgPSAoaXNzZXQoJHRoaXMtPl9yZXNwb25zZS0+X2hlYWRlcnNbJ2NvbnRlbnQtbGVuZ3RoJ10pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHx8IChpc3NldCgkdGhpcy0+X3Jlc3BvbnNlLT5faGVhZGVyc1sndHJhbnNmZXItZW5jb2RpbmcnXSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICYmIHN0cnRvbG93ZXIoJHRoaXMtPl9yZXNwb25zZS0+X2hlYWRlcnNbJ3RyYW5zZmVyLWVuY29kaW5nJ10pID09ICdjaHVua2VkJykpOwogICAgICAgICAgICAgICAgaWYgKCRrZWVwQWxpdmUpIHsKICAgICAgICAgICAgICAgICAgICBpZiAoaXNzZXQoJHRoaXMtPl9yZXNwb25zZS0+X2hlYWRlcnNbJ2Nvbm5lY3Rpb24nXSkpIHsKICAgICAgICAgICAgICAgICAgICAgICAgJGtlZXBBbGl2ZSA9IHN0cnRvbG93ZXIoJHRoaXMtPl9yZXNwb25zZS0+X2hlYWRlcnNbJ2Nvbm5lY3Rpb24nXSkgPT0gJ2tlZXAtYWxpdmUnOwogICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICAgICAgICAgICRrZWVwQWxpdmUgPSAnSFRUUC8nLkhUVFBfUkVRVUVTVF9IVFRQX1ZFUl8xXzEgPT0gJHRoaXMtPl9yZXNwb25zZS0+X3Byb3RvY29sOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgIH0KCiAgICAgICAgaW5pX3NldCgnbWFnaWNfcXVvdGVzX3J1bnRpbWUnLCAkbWFnaWNRdW90ZXMpOwoKICAgICAgICBpZiAoUEVBUjo6aXNFcnJvcigkZXJyKSkgewogICAgICAgICAgICByZXR1cm4gJGVycjsKICAgICAgICB9CgogICAgICAgIGlmICghJGtlZXBBbGl2ZSkgewogICAgICAgICAgICAkdGhpcy0+ZGlzY29ubmVjdCgpOwogICAgICAgIC8vIFN0b3JlIHRoZSBjb25uZWN0ZWQgc29ja2V0IGluICJzdGF0aWMiIHByb3BlcnR5CiAgICAgICAgfSBlbHNlaWYgKGVtcHR5KCRzb2NrZXRzWyRzb2NrS2V5XSkgfHwgZW1wdHkoJHNvY2tldHNbJHNvY2tLZXldLT5mcCkpIHsKICAgICAgICAgICAgJHNvY2tldHNbJHNvY2tLZXldID0mICR0aGlzLT5fc29jazsKICAgICAgICB9CgogICAgICAgIC8vIENoZWNrIGZvciByZWRpcmVjdGlvbgogICAgICAgIGlmICggICAgJHRoaXMtPl9hbGxvd1JlZGlyZWN0cwogICAgICAgICAgICBBTkQgJHRoaXMtPl9yZWRpcmVjdHMgPD0gJHRoaXMtPl9tYXhSZWRpcmVjdHMKICAgICAgICAgICAgQU5EICR0aGlzLT5nZXRSZXNwb25zZUNvZGUoKSA+IDMwMAogICAgICAgICAgICBBTkQgJHRoaXMtPmdldFJlc3BvbnNlQ29kZSgpIDwgMzk5CiAgICAgICAgICAgIEFORCAhZW1wdHkoJHRoaXMtPl9yZXNwb25zZS0+X2hlYWRlcnNbJ2xvY2F0aW9uJ10pKSB7CgoKICAgICAgICAgICAgJHJlZGlyZWN0ID0gJHRoaXMtPl9yZXNwb25zZS0+X2hlYWRlcnNbJ2xvY2F0aW9uJ107CgogICAgICAgICAgICAvLyBBYnNvbHV0ZSBVUkwKICAgICAgICAgICAgaWYgKHByZWdfbWF0Y2goJy9eaHR0cHM/OlwvXC8vaScsICRyZWRpcmVjdCkpIHsKICAgICAgICAgICAgICAgICR0aGlzLT5fdXJsID0gJm5ldyBOZXRfVVJMKCRyZWRpcmVjdCk7CiAgICAgICAgICAgICAgICAkdGhpcy0+YWRkSGVhZGVyKCdIb3N0JywgJHRoaXMtPl9nZW5lcmF0ZUhvc3RIZWFkZXIoKSk7CiAgICAgICAgICAgIC8vIEFic29sdXRlIHBhdGgKICAgICAgICAgICAgfSBlbHNlaWYgKCRyZWRpcmVjdHswfSA9PSAnLycpIHsKICAgICAgICAgICAgICAgICR0aGlzLT5fdXJsLT5wYXRoID0gJHJlZGlyZWN0OwoKICAgICAgICAgICAgLy8gUmVsYXRpdmUgcGF0aAogICAgICAgICAgICB9IGVsc2VpZiAoc3Vic3RyKCRyZWRpcmVjdCwgMCwgMykgPT0gJy4uLycgT1Igc3Vic3RyKCRyZWRpcmVjdCwgMCwgMikgPT0gJy4vJykgewogICAgICAgICAgICAgICAgaWYgKHN1YnN0cigkdGhpcy0+X3VybC0+cGF0aCwgLTEpID09ICcvJykgewogICAgICAgICAgICAgICAgICAgICRyZWRpcmVjdCA9ICR0aGlzLT5fdXJsLT5wYXRoIC4gJHJlZGlyZWN0OwogICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAkcmVkaXJlY3QgPSBkaXJuYW1lKCR0aGlzLT5fdXJsLT5wYXRoKSAuICcvJyAuICRyZWRpcmVjdDsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICRyZWRpcmVjdCA9IE5ldF9VUkw6OnJlc29sdmVQYXRoKCRyZWRpcmVjdCk7CiAgICAgICAgICAgICAgICAkdGhpcy0+X3VybC0+cGF0aCA9ICRyZWRpcmVjdDsKCiAgICAgICAgICAgIC8vIEZpbGVuYW1lLCBubyBwYXRoCiAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICBpZiAoc3Vic3RyKCR0aGlzLT5fdXJsLT5wYXRoLCAtMSkgPT0gJy8nKSB7CiAgICAgICAgICAgICAgICAgICAgJHJlZGlyZWN0ID0gJHRoaXMtPl91cmwtPnBhdGggLiAkcmVkaXJlY3Q7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgICRyZWRpcmVjdCA9IGRpcm5hbWUoJHRoaXMtPl91cmwtPnBhdGgpIC4gJy8nIC4gJHJlZGlyZWN0OwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgJHRoaXMtPl91cmwtPnBhdGggPSAkcmVkaXJlY3Q7CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgICR0aGlzLT5fcmVkaXJlY3RzKys7CiAgICAgICAgICAgIHJldHVybiAkdGhpcy0+c2VuZFJlcXVlc3QoJHNhdmVCb2R5KTsKCiAgICAgICAgLy8gVG9vIG1hbnkgcmVkaXJlY3RzCiAgICAgICAgfSBlbHNlaWYgKCR0aGlzLT5fYWxsb3dSZWRpcmVjdHMgQU5EICR0aGlzLT5fcmVkaXJlY3RzID4gJHRoaXMtPl9tYXhSZWRpcmVjdHMpIHsKICAgICAgICAgICAgcmV0dXJuIFBFQVI6OnJhaXNlRXJyb3IoJ1RvbyBtYW55IHJlZGlyZWN0cycsIEhUVFBfUkVRVUVTVF9FUlJPUl9SRURJUkVDVFMpOwogICAgICAgIH0KCiAgICAgICAgcmV0dXJuIHRydWU7CiAgICB9CgogICAgLyoqCiAgICAgKiBEaXNjb25uZWN0IHRoZSBzb2NrZXQsIGlmIGNvbm5lY3RlZC4gT25seSB1c2VmdWwgaWYgdXNpbmcgS2VlcC1BbGl2ZS4KICAgICAqCiAgICAgKiBAYWNjZXNzIHB1YmxpYwogICAgICovCiAgICBmdW5jdGlvbiBkaXNjb25uZWN0KCkKICAgIHsKICAgICAgICBpZiAoIWVtcHR5KCR0aGlzLT5fc29jaykgJiYgIWVtcHR5KCR0aGlzLT5fc29jay0+ZnApKSB7CiAgICAgICAgICAgICR0aGlzLT5fbm90aWZ5KCdkaXNjb25uZWN0Jyk7CiAgICAgICAgICAgICR0aGlzLT5fc29jay0+ZGlzY29ubmVjdCgpOwogICAgICAgIH0KICAgIH0KCiAgICAvKioKICAgICogUmV0dXJucyB0aGUgcmVzcG9uc2UgY29kZQogICAgKgogICAgKiBAYWNjZXNzIHB1YmxpYwogICAgKiBAcmV0dXJuIG1peGVkICAgICBSZXNwb25zZSBjb2RlLCBmYWxzZSBpZiBub3Qgc2V0CiAgICAqLwogICAgZnVuY3Rpb24gZ2V0UmVzcG9uc2VDb2RlKCkKICAgIHsKICAgICAgICByZXR1cm4gaXNzZXQoJHRoaXMtPl9yZXNwb25zZS0+X2NvZGUpID8gJHRoaXMtPl9yZXNwb25zZS0+X2NvZGUgOiBmYWxzZTsKICAgIH0KCiAgICAvKioKICAgICogUmV0dXJucyB0aGUgcmVzcG9uc2UgcmVhc29uIHBocmFzZQogICAgKgogICAgKiBAYWNjZXNzIHB1YmxpYwogICAgKiBAcmV0dXJuIG1peGVkICAgICBSZXNwb25zZSByZWFzb24gcGhyYXNlLCBmYWxzZSBpZiBub3Qgc2V0CiAgICAqLwogICAgZnVuY3Rpb24gZ2V0UmVzcG9uc2VSZWFzb24oKQogICAgewogICAgICAgIHJldHVybiBpc3NldCgkdGhpcy0+X3Jlc3BvbnNlLT5fcmVhc29uKSA/ICR0aGlzLT5fcmVzcG9uc2UtPl9yZWFzb24gOiBmYWxzZTsKICAgIH0KCiAgICAvKioKICAgICogUmV0dXJucyBlaXRoZXIgdGhlIG5hbWVkIGhlYWRlciBvciBhbGwgaWYgbm8gbmFtZSBnaXZlbgogICAgKgogICAgKiBAYWNjZXNzIHB1YmxpYwogICAgKiBAcGFyYW0gc3RyaW5nICAgICBUaGUgaGVhZGVyIG5hbWUgdG8gcmV0dXJuLCBkbyBub3Qgc2V0IHRvIGdldCBhbGwgaGVhZGVycwogICAgKiBAcmV0dXJuIG1peGVkICAgICBlaXRoZXIgdGhlIHZhbHVlIG9mICRoZWFkZXJuYW1lIChmYWxzZSBpZiBoZWFkZXIgaXMgbm90IHByZXNlbnQpCiAgICAqICAgICAgICAgICAgICAgICAgIG9yIGFuIGFycmF5IG9mIGFsbCBoZWFkZXJzCiAgICAqLwogICAgZnVuY3Rpb24gZ2V0UmVzcG9uc2VIZWFkZXIoJGhlYWRlcm5hbWUgPSBudWxsKQogICAgewogICAgICAgIGlmICghaXNzZXQoJGhlYWRlcm5hbWUpKSB7CiAgICAgICAgICAgIHJldHVybiBpc3NldCgkdGhpcy0+X3Jlc3BvbnNlLT5faGVhZGVycyk/ICR0aGlzLT5fcmVzcG9uc2UtPl9oZWFkZXJzOiBhcnJheSgpOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICRoZWFkZXJuYW1lID0gc3RydG9sb3dlcigkaGVhZGVybmFtZSk7CiAgICAgICAgICAgIHJldHVybiBpc3NldCgkdGhpcy0+X3Jlc3BvbnNlLT5faGVhZGVyc1skaGVhZGVybmFtZV0pID8gJHRoaXMtPl9yZXNwb25zZS0+X2hlYWRlcnNbJGhlYWRlcm5hbWVdIDogZmFsc2U7CiAgICAgICAgfQogICAgfQoKICAgIC8qKgogICAgKiBSZXR1cm5zIHRoZSBib2R5IG9mIHRoZSByZXNwb25zZQogICAgKgogICAgKiBAYWNjZXNzIHB1YmxpYwogICAgKiBAcmV0dXJuIG1peGVkICAgICByZXNwb25zZSBib2R5LCBmYWxzZSBpZiBub3Qgc2V0CiAgICAqLwogICAgZnVuY3Rpb24gZ2V0UmVzcG9uc2VCb2R5KCkKICAgIHsKICAgICAgICByZXR1cm4gaXNzZXQoJHRoaXMtPl9yZXNwb25zZS0+X2JvZHkpID8gJHRoaXMtPl9yZXNwb25zZS0+X2JvZHkgOiBmYWxzZTsKICAgIH0KCiAgICAvKioKICAgICogUmV0dXJucyBjb29raWVzIHNldCBpbiByZXNwb25zZQogICAgKgogICAgKiBAYWNjZXNzIHB1YmxpYwogICAgKiBAcmV0dXJuIG1peGVkICAgICBhcnJheSBvZiByZXNwb25zZSBjb29raWVzLCBmYWxzZSBpZiBub25lIGFyZSBwcmVzZW50CiAgICAqLwogICAgZnVuY3Rpb24gZ2V0UmVzcG9uc2VDb29raWVzKCkKICAgIHsKICAgICAgICByZXR1cm4gaXNzZXQoJHRoaXMtPl9yZXNwb25zZS0+X2Nvb2tpZXMpID8gJHRoaXMtPl9yZXNwb25zZS0+X2Nvb2tpZXMgOiBmYWxzZTsKICAgIH0KCiAgICAvKioKICAgICogQnVpbGRzIHRoZSByZXF1ZXN0IHN0cmluZwogICAgKgogICAgKiBAYWNjZXNzIHByaXZhdGUKICAgICogQHJldHVybiBzdHJpbmcgVGhlIHJlcXVlc3Qgc3RyaW5nCiAgICAqLwogICAgZnVuY3Rpb24gX2J1aWxkUmVxdWVzdCgpCiAgICB7CiAgICAgICAgJHNlcGFyYXRvciA9IGluaV9nZXQoJ2FyZ19zZXBhcmF0b3Iub3V0cHV0Jyk7CiAgICAgICAgaW5pX3NldCgnYXJnX3NlcGFyYXRvci5vdXRwdXQnLCAnJicpOwogICAgICAgICRxdWVyeXN0cmluZyA9ICgkcXVlcnlzdHJpbmcgPSAkdGhpcy0+X3VybC0+Z2V0UXVlcnlTdHJpbmcoKSkgPyAnPycgLiAkcXVlcnlzdHJpbmcgOiAnJzsKICAgICAgICBpbmlfc2V0KCdhcmdfc2VwYXJhdG9yLm91dHB1dCcsICRzZXBhcmF0b3IpOwoKICAgICAgICAkaG9zdCA9IGlzc2V0KCR0aGlzLT5fcHJveHlfaG9zdCkgPyAkdGhpcy0+X3VybC0+cHJvdG9jb2wgLiAnOi8vJyAuICR0aGlzLT5fdXJsLT5ob3N0IDogJyc7CiAgICAgICAgJHBvcnQgPSAoaXNzZXQoJHRoaXMtPl9wcm94eV9ob3N0KSBBTkQgJHRoaXMtPl91cmwtPnBvcnQgIT0gODApID8gJzonIC4gJHRoaXMtPl91cmwtPnBvcnQgOiAnJzsKICAgICAgICAkcGF0aCA9ICR0aGlzLT5fdXJsLT5wYXRoIC4gJHF1ZXJ5c3RyaW5nOwogICAgICAgICR1cmwgID0gJGhvc3QgLiAkcG9ydCAuICRwYXRoOwoKICAgICAgICBpZiAoIXN0cmxlbigkdXJsKSkgewogICAgICAgICAgICAkdXJsID0gJy8nOwogICAgICAgIH0KCiAgICAgICAgJHJlcXVlc3QgPSAkdGhpcy0+X21ldGhvZCAuICcgJyAuICR1cmwgLiAnIEhUVFAvJyAuICR0aGlzLT5faHR0cCAuICJcclxuIjsKCiAgICAgICAgaWYgKGluX2FycmF5KCR0aGlzLT5fbWV0aG9kLCAkdGhpcy0+X2JvZHlEaXNhbGxvd2VkKSB8fAogICAgICAgICAgICAoMCA9PSBzdHJsZW4oJHRoaXMtPl9ib2R5KSAmJiAoSFRUUF9SRVFVRVNUX01FVEhPRF9QT1NUICE9ICR0aGlzLT5fbWV0aG9kIHx8CiAgICAgICAgICAgICAoZW1wdHkoJHRoaXMtPl9wb3N0RGF0YSkgJiYgZW1wdHkoJHRoaXMtPl9wb3N0RmlsZXMpKSkpKQogICAgICAgIHsKICAgICAgICAgICAgJHRoaXMtPnJlbW92ZUhlYWRlcignQ29udGVudC1UeXBlJyk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgaWYgKGVtcHR5KCR0aGlzLT5fcmVxdWVzdEhlYWRlcnNbJ2NvbnRlbnQtdHlwZSddKSkgewogICAgICAgICAgICAgICAgLy8gQWRkIGRlZmF1bHQgY29udGVudC10eXBlCiAgICAgICAgICAgICAgICAkdGhpcy0+YWRkSGVhZGVyKCdDb250ZW50LVR5cGUnLCAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyk7CiAgICAgICAgICAgIH0gZWxzZWlmICgnbXVsdGlwYXJ0L2Zvcm0tZGF0YScgPT0gJHRoaXMtPl9yZXF1ZXN0SGVhZGVyc1snY29udGVudC10eXBlJ10pIHsKICAgICAgICAgICAgICAgICRib3VuZGFyeSA9ICdIVFRQX1JlcXVlc3RfJyAuIG1kNSh1bmlxaWQoJ3JlcXVlc3QnKSAuIG1pY3JvdGltZSgpKTsKICAgICAgICAgICAgICAgICR0aGlzLT5hZGRIZWFkZXIoJ0NvbnRlbnQtVHlwZScsICdtdWx0aXBhcnQvZm9ybS1kYXRhOyBib3VuZGFyeT0nIC4gJGJvdW5kYXJ5KTsKICAgICAgICAgICAgfQogICAgICAgIH0KCiAgICAgICAgLy8gUmVxdWVzdCBIZWFkZXJzCiAgICAgICAgaWYgKCFlbXB0eSgkdGhpcy0+X3JlcXVlc3RIZWFkZXJzKSkgewogICAgICAgICAgICBmb3JlYWNoICgkdGhpcy0+X3JlcXVlc3RIZWFkZXJzIGFzICRuYW1lID0+ICR2YWx1ZSkgewogICAgICAgICAgICAgICAgJGNhbm9uaWNhbE5hbWUgPSBpbXBsb2RlKCctJywgYXJyYXlfbWFwKCd1Y2ZpcnN0JywgZXhwbG9kZSgnLScsICRuYW1lKSkpOwogICAgICAgICAgICAgICAgJHJlcXVlc3QgICAgICAuPSAkY2Fub25pY2FsTmFtZSAuICc6ICcgLiAkdmFsdWUgLiAiXHJcbiI7CiAgICAgICAgICAgIH0KICAgICAgICB9CgogICAgICAgIC8vIE1ldGhvZCBkb2VzIG5vdCBhbGxvdyBhIGJvZHksIHNpbXBseSBhZGQgYSBmaW5hbCBDUkxGCiAgICAgICAgaWYgKGluX2FycmF5KCR0aGlzLT5fbWV0aG9kLCAkdGhpcy0+X2JvZHlEaXNhbGxvd2VkKSkgewoKICAgICAgICAgICAgJHJlcXVlc3QgLj0gIlxyXG4iOwoKICAgICAgICAvLyBQb3N0IGRhdGEgaWYgaXQncyBhbiBhcnJheQogICAgICAgIH0gZWxzZWlmIChIVFRQX1JFUVVFU1RfTUVUSE9EX1BPU1QgPT0gJHRoaXMtPl9tZXRob2QgJiYKICAgICAgICAgICAgICAgICAgKCFlbXB0eSgkdGhpcy0+X3Bvc3REYXRhKSB8fCAhZW1wdHkoJHRoaXMtPl9wb3N0RmlsZXMpKSkgewoKICAgICAgICAgICAgLy8gIm5vcm1hbCIgUE9TVCByZXF1ZXN0CiAgICAgICAgICAgIGlmICghaXNzZXQoJGJvdW5kYXJ5KSkgewogICAgICAgICAgICAgICAgJHBvc3RkYXRhID0gaW1wbG9kZSgnJicsIGFycmF5X21hcCgKICAgICAgICAgICAgICAgICAgICBjcmVhdGVfZnVuY3Rpb24oJyRhJywgJ3JldHVybiAkYVswXSAuIFwnPVwnIC4gJGFbMV07JyksCiAgICAgICAgICAgICAgICAgICAgJHRoaXMtPl9mbGF0dGVuQXJyYXkoJycsICR0aGlzLT5fcG9zdERhdGEpCiAgICAgICAgICAgICAgICApKTsKCiAgICAgICAgICAgIC8vIG11bHRpcGFydCByZXF1ZXN0LCBwcm9iYWJseSB3aXRoIGZpbGUgdXBsb2FkcwogICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgJHBvc3RkYXRhID0gJyc7CiAgICAgICAgICAgICAgICBpZiAoIWVtcHR5KCR0aGlzLT5fcG9zdERhdGEpKSB7CiAgICAgICAgICAgICAgICAgICAgJGZsYXREYXRhID0gJHRoaXMtPl9mbGF0dGVuQXJyYXkoJycsICR0aGlzLT5fcG9zdERhdGEpOwogICAgICAgICAgICAgICAgICAgIGZvcmVhY2ggKCRmbGF0RGF0YSBhcyAkaXRlbSkgewogICAgICAgICAgICAgICAgICAgICAgICAkcG9zdGRhdGEgLj0gJy0tJyAuICRib3VuZGFyeSAuICJcclxuIjsKICAgICAgICAgICAgICAgICAgICAgICAgJHBvc3RkYXRhIC49ICdDb250ZW50LURpc3Bvc2l0aW9uOiBmb3JtLWRhdGE7IG5hbWU9IicgLiAkaXRlbVswXSAuICciJzsKICAgICAgICAgICAgICAgICAgICAgICAgJHBvc3RkYXRhIC49ICJcclxuXHJcbiIgLiB1cmxkZWNvZGUoJGl0ZW1bMV0pIC4gIlxyXG4iOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGZvcmVhY2ggKCR0aGlzLT5fcG9zdEZpbGVzIGFzICRuYW1lID0+ICR2YWx1ZSkgewogICAgICAgICAgICAgICAgICAgIGlmIChpc19hcnJheSgkdmFsdWVbJ25hbWUnXSkpIHsKICAgICAgICAgICAgICAgICAgICAgICAgJHZhcm5hbWUgICAgICAgPSAkbmFtZSAuICgkdGhpcy0+X3VzZUJyYWNrZXRzPyAnW10nOiAnJyk7CiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAgICAgJHZhcm5hbWUgICAgICAgPSAkbmFtZTsKICAgICAgICAgICAgICAgICAgICAgICAgJHZhbHVlWyduYW1lJ10gPSBhcnJheSgkdmFsdWVbJ25hbWUnXSk7CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIGZvcmVhY2ggKCR2YWx1ZVsnbmFtZSddIGFzICRrZXkgPT4gJGZpbGVuYW1lKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICRmcCAgICAgICA9IGZvcGVuKCRmaWxlbmFtZSwgJ3InKTsKICAgICAgICAgICAgICAgICAgICAgICAgJGJhc2VuYW1lID0gYmFzZW5hbWUoJGZpbGVuYW1lKTsKICAgICAgICAgICAgICAgICAgICAgICAgJHR5cGUgICAgID0gaXNfYXJyYXkoJHZhbHVlWyd0eXBlJ10pPyBAJHZhbHVlWyd0eXBlJ11bJGtleV06ICR2YWx1ZVsndHlwZSddOwoKICAgICAgICAgICAgICAgICAgICAgICAgJHBvc3RkYXRhIC49ICctLScgLiAkYm91bmRhcnkgLiAiXHJcbiI7CiAgICAgICAgICAgICAgICAgICAgICAgICRwb3N0ZGF0YSAuPSAnQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSInIC4gJHZhcm5hbWUgLiAnIjsgZmlsZW5hbWU9IicgLiAkYmFzZW5hbWUgLiAnIic7CiAgICAgICAgICAgICAgICAgICAgICAgICRwb3N0ZGF0YSAuPSAiXHJcbkNvbnRlbnQtVHlwZTogIiAuICR0eXBlOwogICAgICAgICAgICAgICAgICAgICAgICAkcG9zdGRhdGEgLj0gIlxyXG5cclxuIiAuIGZyZWFkKCRmcCwgZmlsZXNpemUoJGZpbGVuYW1lKSkgLiAiXHJcbiI7CiAgICAgICAgICAgICAgICAgICAgICAgIGZjbG9zZSgkZnApOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICRwb3N0ZGF0YSAuPSAnLS0nIC4gJGJvdW5kYXJ5IC4gIi0tXHJcbiI7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgJHJlcXVlc3QgLj0gJ0NvbnRlbnQtTGVuZ3RoOiAnIC4KICAgICAgICAgICAgICAgICAgICAgICAgKEhUVFBfUkVRVUVTVF9NQlNUUklORz8gbWJfc3RybGVuKCRwb3N0ZGF0YSwgJ2lzby04ODU5LTEnKTogc3RybGVuKCRwb3N0ZGF0YSkpIC4KICAgICAgICAgICAgICAgICAgICAgICAgIlxyXG5cclxuIjsKICAgICAgICAgICAgJHJlcXVlc3QgLj0gJHBvc3RkYXRhOwoKICAgICAgICAvLyBFeHBsaWNpdGx5IHNldCByZXF1ZXN0IGJvZHkKICAgICAgICB9IGVsc2VpZiAoMCA8IHN0cmxlbigkdGhpcy0+X2JvZHkpKSB7CgogICAgICAgICAgICAkcmVxdWVzdCAuPSAnQ29udGVudC1MZW5ndGg6ICcgLgogICAgICAgICAgICAgICAgICAgICAgICAoSFRUUF9SRVFVRVNUX01CU1RSSU5HPyBtYl9zdHJsZW4oJHRoaXMtPl9ib2R5LCAnaXNvLTg4NTktMScpOiBzdHJsZW4oJHRoaXMtPl9ib2R5KSkgLgogICAgICAgICAgICAgICAgICAgICAgICAiXHJcblxyXG4iOwogICAgICAgICAgICAkcmVxdWVzdCAuPSAkdGhpcy0+X2JvZHk7CgogICAgICAgIC8vIE5vIGJvZHk6IHNlbmQgYSBDb250ZW50LUxlbmd0aCBoZWFkZXIgbm9uZXRoZWxlc3MgKHJlcXVlc3QgIzEyOTAwKSwKICAgICAgICAvLyBidXQgZG8gdGhhdCBvbmx5IGZvciBtZXRob2RzIHRoYXQgcmVxdWlyZSBhIGJvZHkgKGJ1ZyAjMTQ3NDApCiAgICAgICAgfSBlbHNlIHsKCiAgICAgICAgICAgIGlmIChpbl9hcnJheSgkdGhpcy0+X21ldGhvZCwgJHRoaXMtPl9ib2R5UmVxdWlyZWQpKSB7CiAgICAgICAgICAgICAgICAkcmVxdWVzdCAuPSAiQ29udGVudC1MZW5ndGg6IDBcclxuIjsKICAgICAgICAgICAgfQogICAgICAgICAgICAkcmVxdWVzdCAuPSAiXHJcbiI7CiAgICAgICAgfQoKICAgICAgICByZXR1cm4gJHJlcXVlc3Q7CiAgICB9CgogICAvKioKICAgICogSGVscGVyIGZ1bmN0aW9uIHRvIGNoYW5nZSB0aGUgKHByb2JhYmx5IG11bHRpZGltZW5zaW9uYWwpIGFzc29jaWF0aXZlIGFycmF5CiAgICAqIGludG8gdGhlIHNpbXBsZSBvbmUuCiAgICAqCiAgICAqIEBwYXJhbSAgICBzdHJpbmcgIG5hbWUgZm9yIGl0ZW0KICAgICogQHBhcmFtICAgIG1peGVkICAgaXRlbSdzIHZhbHVlcwogICAgKiBAcmV0dXJuICAgYXJyYXkgICBhcnJheSB3aXRoIHRoZSBmb2xsb3dpbmcgaXRlbXM6IGFycmF5KCdpdGVtIG5hbWUnLCAnaXRlbSB2YWx1ZScpOwogICAgKiBAYWNjZXNzICAgcHJpdmF0ZQogICAgKi8KICAgIGZ1bmN0aW9uIF9mbGF0dGVuQXJyYXkoJG5hbWUsICR2YWx1ZXMpCiAgICB7CiAgICAgICAgaWYgKCFpc19hcnJheSgkdmFsdWVzKSkgewogICAgICAgICAgICByZXR1cm4gYXJyYXkoYXJyYXkoJG5hbWUsICR2YWx1ZXMpKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAkcmV0ID0gYXJyYXkoKTsKICAgICAgICAgICAgZm9yZWFjaCAoJHZhbHVlcyBhcyAkayA9PiAkdikgewogICAgICAgICAgICAgICAgaWYgKGVtcHR5KCRuYW1lKSkgewogICAgICAgICAgICAgICAgICAgICRuZXdOYW1lID0gJGs7CiAgICAgICAgICAgICAgICB9IGVsc2VpZiAoJHRoaXMtPl91c2VCcmFja2V0cykgewogICAgICAgICAgICAgICAgICAgICRuZXdOYW1lID0gJG5hbWUgLiAnWycgLiAkayAuICddJzsKICAgICAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICAgICAgJG5ld05hbWUgPSAkbmFtZTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICRyZXQgPSBhcnJheV9tZXJnZSgkcmV0LCAkdGhpcy0+X2ZsYXR0ZW5BcnJheSgkbmV3TmFtZSwgJHYpKTsKICAgICAgICAgICAgfQogICAgICAgICAgICByZXR1cm4gJHJldDsKICAgICAgICB9CiAgICB9CgoKICAgLyoqCiAgICAqIEFkZHMgYSBMaXN0ZW5lciB0byB0aGUgbGlzdCBvZiBsaXN0ZW5lcnMgdGhhdCBhcmUgbm90aWZpZWQgb2YKICAgICogdGhlIG9iamVjdCdzIGV2ZW50cwogICAgKgogICAgKiBFdmVudHMgc2VudCBieSBIVFRQX1JlcXVlc3Qgb2JqZWN0CiAgICAqIC0gJ2Nvbm5lY3QnOiBvbiBjb25uZWN0aW9uIHRvIHNlcnZlcgogICAgKiAtICdzZW50UmVxdWVzdCc6IGFmdGVyIHRoZSByZXF1ZXN0IHdhcyBzZW50CiAgICAqIC0gJ2Rpc2Nvbm5lY3QnOiBvbiBkaXNjb25uZWN0aW9uIGZyb20gc2VydmVyCiAgICAqCiAgICAqIEV2ZW50cyBzZW50IGJ5IEhUVFBfUmVzcG9uc2Ugb2JqZWN0CiAgICAqIC0gJ2dvdEhlYWRlcnMnOiBhZnRlciByZWNlaXZpbmcgcmVzcG9uc2UgaGVhZGVycyAoaGVhZGVycyBhcmUgcGFzc2VkIGluICRkYXRhKQogICAgKiAtICd0aWNrJzogb24gcmVjZWl2aW5nIGEgcGFydCBvZiByZXNwb25zZSBib2R5ICh0aGUgcGFydCBpcyBwYXNzZWQgaW4gJGRhdGEpCiAgICAqIC0gJ2d6VGljayc6IG9uIHJlY2VpdmluZyBhIGd6aXAtZW5jb2RlZCBwYXJ0IG9mIHJlc3BvbnNlIGJvZHkgKGRpdHRvKQogICAgKiAtICdnb3RCb2R5JzogYWZ0ZXIgcmVjZWl2aW5nIHRoZSByZXNwb25zZSBib2R5IChwYXNzZXMgdGhlIGRlY29kZWQgYm9keSBpbiAkZGF0YSBpZiBpdCB3YXMgZ3ppcHBlZCkKICAgICoKICAgICogQHBhcmFtICAgIEhUVFBfUmVxdWVzdF9MaXN0ZW5lciAgIGxpc3RlbmVyIHRvIGF0dGFjaAogICAgKiBAcmV0dXJuICAgYm9vbGVhbiAgICAgICAgICAgICAgICAgd2hldGhlciB0aGUgbGlzdGVuZXIgd2FzIHN1Y2Nlc3NmdWxseSBhdHRhY2hlZAogICAgKiBAYWNjZXNzICAgcHVibGljCiAgICAqLwogICAgZnVuY3Rpb24gYXR0YWNoKCYkbGlzdGVuZXIpCiAgICB7CiAgICAgICAgaWYgKCFpc19hKCRsaXN0ZW5lciwgJ0hUVFBfUmVxdWVzdF9MaXN0ZW5lcicpKSB7CiAgICAgICAgICAgIHJldHVybiBmYWxzZTsKICAgICAgICB9CiAgICAgICAgJHRoaXMtPl9saXN0ZW5lcnNbJGxpc3RlbmVyLT5nZXRJZCgpXSA9JiAkbGlzdGVuZXI7CiAgICAgICAgcmV0dXJuIHRydWU7CiAgICB9CgoKICAgLyoqCiAgICAqIFJlbW92ZXMgYSBMaXN0ZW5lciBmcm9tIHRoZSBsaXN0IG9mIGxpc3RlbmVycwogICAgKgogICAgKiBAcGFyYW0gICAgSFRUUF9SZXF1ZXN0X0xpc3RlbmVyICAgbGlzdGVuZXIgdG8gZGV0YWNoCiAgICAqIEByZXR1cm4gICBib29sZWFuICAgICAgICAgICAgICAgICB3aGV0aGVyIHRoZSBsaXN0ZW5lciB3YXMgc3VjY2Vzc2Z1bGx5IGRldGFjaGVkCiAgICAqIEBhY2Nlc3MgICBwdWJsaWMKICAgICovCiAgICBmdW5jdGlvbiBkZXRhY2goJiRsaXN0ZW5lcikKICAgIHsKICAgICAgICBpZiAoIWlzX2EoJGxpc3RlbmVyLCAnSFRUUF9SZXF1ZXN0X0xpc3RlbmVyJykgfHwKICAgICAgICAgICAgIWlzc2V0KCR0aGlzLT5fbGlzdGVuZXJzWyRsaXN0ZW5lci0+Z2V0SWQoKV0pKSB7CiAgICAgICAgICAgIHJldHVybiBmYWxzZTsKICAgICAgICB9CiAgICAgICAgdW5zZXQoJHRoaXMtPl9saXN0ZW5lcnNbJGxpc3RlbmVyLT5nZXRJZCgpXSk7CiAgICAgICAgcmV0dXJuIHRydWU7CiAgICB9CgoKICAgLyoqCiAgICAqIE5vdGlmaWVzIGFsbCByZWdpc3RlcmVkIGxpc3RlbmVycyBvZiBhbiBldmVudC4KICAgICoKICAgICogQHBhcmFtICAgIHN0cmluZyAgRXZlbnQgbmFtZQogICAgKiBAcGFyYW0gICAgbWl4ZWQgICBBZGRpdGlvbmFsIGRhdGEKICAgICogQGFjY2VzcyAgIHByaXZhdGUKICAgICogQHNlZSAgICAgIEhUVFBfUmVxdWVzdDo6YXR0YWNoKCkKICAgICovCiAgICBmdW5jdGlvbiBfbm90aWZ5KCRldmVudCwgJGRhdGEgPSBudWxsKQogICAgewogICAgICAgIGZvcmVhY2ggKGFycmF5X2tleXMoJHRoaXMtPl9saXN0ZW5lcnMpIGFzICRpZCkgewogICAgICAgICAgICAkdGhpcy0+X2xpc3RlbmVyc1skaWRdLT51cGRhdGUoJHRoaXMsICRldmVudCwgJGRhdGEpOwogICAgICAgIH0KICAgIH0KfQoKCi8qKgogKiBSZXNwb25zZSBjbGFzcyB0byBjb21wbGVtZW50IHRoZSBSZXF1ZXN0IGNsYXNzCiAqCiAqIEBjYXRlZ29yeSAgICBIVFRQCiAqIEBwYWNrYWdlICAgICBIVFRQX1JlcXVlc3QKICogQGF1dGhvciAgICAgIFJpY2hhcmQgSGV5ZXMgPHJpY2hhcmRAcGhwZ3VydS5vcmc+CiAqIEBhdXRob3IgICAgICBBbGV4ZXkgQm9yem92IDxhdmJAcGhwLm5ldD4KICogQHZlcnNpb24gICAgIFJlbGVhc2U6IDEuNC40CiAqLwpjbGFzcyBIVFRQX1Jlc3BvbnNlCnsKICAgIC8qKgogICAgKiBTb2NrZXQgb2JqZWN0CiAgICAqIEB2YXIgTmV0X1NvY2tldAogICAgKi8KICAgIHZhciAkX3NvY2s7CgogICAgLyoqCiAgICAqIFByb3RvY29sCiAgICAqIEB2YXIgc3RyaW5nCiAgICAqLwogICAgdmFyICRfcHJvdG9jb2w7CgogICAgLyoqCiAgICAqIFJldHVybiBjb2RlCiAgICAqIEB2YXIgc3RyaW5nCiAgICAqLwogICAgdmFyICRfY29kZTsKCiAgICAvKioKICAgICogUmVzcG9uc2UgcmVhc29uIHBocmFzZQogICAgKiBAdmFyIHN0cmluZwogICAgKi8KICAgIHZhciAkX3JlYXNvbjsKCiAgICAvKioKICAgICogUmVzcG9uc2UgaGVhZGVycwogICAgKiBAdmFyIGFycmF5CiAgICAqLwogICAgdmFyICRfaGVhZGVyczsKCiAgICAvKioKICAgICogQ29va2llcyBzZXQgaW4gcmVzcG9uc2UKICAgICogQHZhciBhcnJheQogICAgKi8KICAgIHZhciAkX2Nvb2tpZXM7CgogICAgLyoqCiAgICAqIFJlc3BvbnNlIGJvZHkKICAgICogQHZhciBzdHJpbmcKICAgICovCiAgICB2YXIgJF9ib2R5ID0gJyc7CgogICAvKioKICAgICogVXNlZCBieSBfcmVhZENodW5rZWQoKTogcmVtYWluaW5nIGxlbmd0aCBvZiB0aGUgY3VycmVudCBjaHVuawogICAgKiBAdmFyIHN0cmluZwogICAgKi8KICAgIHZhciAkX2NodW5rTGVuZ3RoID0gMDsKCiAgIC8qKgogICAgKiBBdHRhY2hlZCBsaXN0ZW5lcnMKICAgICogQHZhciBhcnJheQogICAgKi8KICAgIHZhciAkX2xpc3RlbmVycyA9IGFycmF5KCk7CgogICAvKioKICAgICogQnl0ZXMgbGVmdCB0byByZWFkIGZyb20gbWVzc2FnZS1ib2R5CiAgICAqIEB2YXIgbnVsbHxpbnQKICAgICovCiAgICB2YXIgJF90b1JlYWQ7CgogICAgLyoqCiAgICAqIENvbnN0cnVjdG9yCiAgICAqCiAgICAqIEBwYXJhbSAgTmV0X1NvY2tldCAgICBzb2NrZXQgdG8gcmVhZCB0aGUgcmVzcG9uc2UgZnJvbQogICAgKiBAcGFyYW0gIGFycmF5ICAgICAgICAgbGlzdGVuZXJzIGF0dGFjaGVkIHRvIHJlcXVlc3QKICAgICovCiAgICBmdW5jdGlvbiBIVFRQX1Jlc3BvbnNlKCYkc29jaywgJiRsaXN0ZW5lcnMpCiAgICB7CiAgICAgICAgJHRoaXMtPl9zb2NrICAgICAgPSYgJHNvY2s7CiAgICAgICAgJHRoaXMtPl9saXN0ZW5lcnMgPSYgJGxpc3RlbmVyczsKICAgIH0KCgogICAvKioKICAgICogUHJvY2Vzc2VzIGEgSFRUUCByZXNwb25zZQogICAgKgogICAgKiBUaGlzIGV4dHJhY3RzIHJlc3BvbnNlIGNvZGUsIGhlYWRlcnMsIGNvb2tpZXMgYW5kIGRlY29kZXMgYm9keSBpZiBpdAogICAgKiB3YXMgZW5jb2RlZCBpbiBzb21lIHdheQogICAgKgogICAgKiBAYWNjZXNzIHB1YmxpYwogICAgKiBAcGFyYW0gIGJvb2wgICAgICBXaGV0aGVyIHRvIHN0b3JlIHJlc3BvbnNlIGJvZHkgaW4gb2JqZWN0IHByb3BlcnR5LCBzZXQKICAgICogICAgICAgICAgICAgICAgICAgdGhpcyB0byBmYWxzZSBpZiBkb3dubG9hZGluZyBhIExBUkdFIGZpbGUgYW5kIHVzaW5nIGEgTGlzdGVuZXIuCiAgICAqICAgICAgICAgICAgICAgICAgIFRoaXMgaXMgYXNzdW1lZCB0byBiZSB0cnVlIGlmIGJvZHkgaXMgZ3ppcC1lbmNvZGVkLgogICAgKiBAcGFyYW0gIGJvb2wgICAgICBXaGV0aGVyIHRoZSByZXNwb25zZSBjYW4gYWN0dWFsbHkgaGF2ZSBhIG1lc3NhZ2UtYm9keS4KICAgICogICAgICAgICAgICAgICAgICAgV2lsbCBiZSBzZXQgdG8gZmFsc2UgZm9yIEhFQUQgcmVxdWVzdHMuCiAgICAqIEB0aHJvd3MgUEVBUl9FcnJvcgogICAgKiBAcmV0dXJuIG1peGVkICAgICB0cnVlIG9uIHN1Y2Nlc3MsIFBFQVJfRXJyb3IgaW4gY2FzZSBvZiBtYWxmb3JtZWQgcmVzcG9uc2UKICAgICovCiAgICBmdW5jdGlvbiBwcm9jZXNzKCRzYXZlQm9keSA9IHRydWUsICRjYW5IYXZlQm9keSA9IHRydWUpCiAgICB7CiAgICAgICAgZG8gewogICAgICAgICAgICAkbGluZSA9ICR0aGlzLT5fc29jay0+cmVhZExpbmUoKTsKICAgICAgICAgICAgaWYgKCFwcmVnX21hdGNoKCchXihIVFRQL1xkXC5cZCkgKFxkezN9KSg/OiAoLispKT8hJywgJGxpbmUsICRzKSkgewogICAgICAgICAgICAgICAgcmV0dXJuIFBFQVI6OnJhaXNlRXJyb3IoJ01hbGZvcm1lZCByZXNwb25zZScsIEhUVFBfUkVRVUVTVF9FUlJPUl9SRVNQT05TRSk7CiAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICAkdGhpcy0+X3Byb3RvY29sID0gJHNbMV07CiAgICAgICAgICAgICAgICAkdGhpcy0+X2NvZGUgICAgID0gaW50dmFsKCRzWzJdKTsKICAgICAgICAgICAgICAgICR0aGlzLT5fcmVhc29uICAgPSBlbXB0eSgkc1szXSk/IG51bGw6ICRzWzNdOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHdoaWxlICgnJyAhPT0gKCRoZWFkZXIgPSAkdGhpcy0+X3NvY2stPnJlYWRMaW5lKCkpKSB7CiAgICAgICAgICAgICAgICAkdGhpcy0+X3Byb2Nlc3NIZWFkZXIoJGhlYWRlcik7CiAgICAgICAgICAgIH0KICAgICAgICB9IHdoaWxlICgxMDAgPT0gJHRoaXMtPl9jb2RlKTsKCiAgICAgICAgJHRoaXMtPl9ub3RpZnkoJ2dvdEhlYWRlcnMnLCAkdGhpcy0+X2hlYWRlcnMpOwoKICAgICAgICAvLyBSRkMgMjYxNiwgc2VjdGlvbiA0LjQ6CiAgICAgICAgLy8gMS4gQW55IHJlc3BvbnNlIG1lc3NhZ2Ugd2hpY2ggIk1VU1QgTk9UIiBpbmNsdWRlIGEgbWVzc2FnZS1ib2R5IC4uLgogICAgICAgIC8vIGlzIGFsd2F5cyB0ZXJtaW5hdGVkIGJ5IHRoZSBmaXJzdCBlbXB0eSBsaW5lIGFmdGVyIHRoZSBoZWFkZXIgZmllbGRzCiAgICAgICAgLy8gMy4gLi4uIElmIGEgbWVzc2FnZSBpcyByZWNlaXZlZCB3aXRoIGJvdGggYQogICAgICAgIC8vIFRyYW5zZmVyLUVuY29kaW5nIGhlYWRlciBmaWVsZCBhbmQgYSBDb250ZW50LUxlbmd0aCBoZWFkZXIgZmllbGQsCiAgICAgICAgLy8gdGhlIGxhdHRlciBNVVNUIGJlIGlnbm9yZWQuCiAgICAgICAgJGNhbkhhdmVCb2R5ID0gJGNhbkhhdmVCb2R5ICYmICR0aGlzLT5fY29kZSA+PSAyMDAgJiYKICAgICAgICAgICAgICAgICAgICAgICAkdGhpcy0+X2NvZGUgIT0gMjA0ICYmICR0aGlzLT5fY29kZSAhPSAzMDQ7CgogICAgICAgIC8vIElmIHJlc3BvbnNlIGJvZHkgaXMgcHJlc2VudCwgcmVhZCBpdCBhbmQgZGVjb2RlCiAgICAgICAgJGNodW5rZWQgPSBpc3NldCgkdGhpcy0+X2hlYWRlcnNbJ3RyYW5zZmVyLWVuY29kaW5nJ10pICYmICgnY2h1bmtlZCcgPT0gJHRoaXMtPl9oZWFkZXJzWyd0cmFuc2Zlci1lbmNvZGluZyddKTsKICAgICAgICAkZ3ppcHBlZCA9IGlzc2V0KCR0aGlzLT5faGVhZGVyc1snY29udGVudC1lbmNvZGluZyddKSAmJiAoJ2d6aXAnID09ICR0aGlzLT5faGVhZGVyc1snY29udGVudC1lbmNvZGluZyddKTsKICAgICAgICAkaGFzQm9keSA9IGZhbHNlOwogICAgICAgIGlmICgkY2FuSGF2ZUJvZHkgJiYgKCRjaHVua2VkIHx8ICFpc3NldCgkdGhpcy0+X2hlYWRlcnNbJ2NvbnRlbnQtbGVuZ3RoJ10pIHx8CiAgICAgICAgICAgICAgICAwICE9ICR0aGlzLT5faGVhZGVyc1snY29udGVudC1sZW5ndGgnXSkpCiAgICAgICAgewogICAgICAgICAgICBpZiAoJGNodW5rZWQgfHwgIWlzc2V0KCR0aGlzLT5faGVhZGVyc1snY29udGVudC1sZW5ndGgnXSkpIHsKICAgICAgICAgICAgICAgICR0aGlzLT5fdG9SZWFkID0gbnVsbDsKICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICR0aGlzLT5fdG9SZWFkID0gJHRoaXMtPl9oZWFkZXJzWydjb250ZW50LWxlbmd0aCddOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHdoaWxlICghJHRoaXMtPl9zb2NrLT5lb2YoKSAmJiAoaXNfbnVsbCgkdGhpcy0+X3RvUmVhZCkgfHwgMCA8ICR0aGlzLT5fdG9SZWFkKSkgewogICAgICAgICAgICAgICAgaWYgKCRjaHVua2VkKSB7CiAgICAgICAgICAgICAgICAgICAgJGRhdGEgPSAkdGhpcy0+X3JlYWRDaHVua2VkKCk7CiAgICAgICAgICAgICAgICB9IGVsc2VpZiAoaXNfbnVsbCgkdGhpcy0+X3RvUmVhZCkpIHsKICAgICAgICAgICAgICAgICAgICAkZGF0YSA9ICR0aGlzLT5fc29jay0+cmVhZCg0MDk2KTsKICAgICAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICAgICAgJGRhdGEgPSAkdGhpcy0+X3NvY2stPnJlYWQobWluKDQwOTYsICR0aGlzLT5fdG9SZWFkKSk7CiAgICAgICAgICAgICAgICAgICAgJHRoaXMtPl90b1JlYWQgLT0gSFRUUF9SRVFVRVNUX01CU1RSSU5HPyBtYl9zdHJsZW4oJGRhdGEsICdpc28tODg1OS0xJyk6IHN0cmxlbigkZGF0YSk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBpZiAoJycgPT0gJGRhdGEgJiYgKCEkdGhpcy0+X2NodW5rTGVuZ3RoIHx8ICR0aGlzLT5fc29jay0+ZW9mKCkpKSB7CiAgICAgICAgICAgICAgICAgICAgYnJlYWs7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgICRoYXNCb2R5ID0gdHJ1ZTsKICAgICAgICAgICAgICAgICAgICBpZiAoJHNhdmVCb2R5IHx8ICRnemlwcGVkKSB7CiAgICAgICAgICAgICAgICAgICAgICAgICR0aGlzLT5fYm9keSAuPSAkZGF0YTsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgJHRoaXMtPl9ub3RpZnkoJGd6aXBwZWQ/ICdnelRpY2snOiAndGljaycsICRkYXRhKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgIH0KCiAgICAgICAgaWYgKCRoYXNCb2R5KSB7CiAgICAgICAgICAgIC8vIFVuY29tcHJlc3MgdGhlIGJvZHkgaWYgbmVlZGVkCiAgICAgICAgICAgIGlmICgkZ3ppcHBlZCkgewogICAgICAgICAgICAgICAgJGJvZHkgPSAkdGhpcy0+X2RlY29kZUd6aXAoJHRoaXMtPl9ib2R5KTsKICAgICAgICAgICAgICAgIGlmIChQRUFSOjppc0Vycm9yKCRib2R5KSkgewogICAgICAgICAgICAgICAgICAgIHJldHVybiAkYm9keTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICR0aGlzLT5fYm9keSA9ICRib2R5OwogICAgICAgICAgICAgICAgJHRoaXMtPl9ub3RpZnkoJ2dvdEJvZHknLCAkdGhpcy0+X2JvZHkpOwogICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgJHRoaXMtPl9ub3RpZnkoJ2dvdEJvZHknKTsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICByZXR1cm4gdHJ1ZTsKICAgIH0KCgogICAvKioKICAgICogUHJvY2Vzc2VzIHRoZSByZXNwb25zZSBoZWFkZXIKICAgICoKICAgICogQGFjY2VzcyBwcml2YXRlCiAgICAqIEBwYXJhbSAgc3RyaW5nICAgIEhUVFAgaGVhZGVyCiAgICAqLwogICAgZnVuY3Rpb24gX3Byb2Nlc3NIZWFkZXIoJGhlYWRlcikKICAgIHsKICAgICAgICBpZiAoZmFsc2UgPT09IHN0cnBvcygkaGVhZGVyLCAnOicpKSB7CiAgICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgbGlzdCgkaGVhZGVybmFtZSwgJGhlYWRlcnZhbHVlKSA9IGV4cGxvZGUoJzonLCAkaGVhZGVyLCAyKTsKICAgICAgICAkaGVhZGVybmFtZSAgPSBzdHJ0b2xvd2VyKCRoZWFkZXJuYW1lKTsKICAgICAgICAkaGVhZGVydmFsdWUgPSBsdHJpbSgkaGVhZGVydmFsdWUpOwoKICAgICAgICBpZiAoJ3NldC1jb29raWUnICE9ICRoZWFkZXJuYW1lKSB7CiAgICAgICAgICAgIGlmIChpc3NldCgkdGhpcy0+X2hlYWRlcnNbJGhlYWRlcm5hbWVdKSkgewogICAgICAgICAgICAgICAgJHRoaXMtPl9oZWFkZXJzWyRoZWFkZXJuYW1lXSAuPSAnLCcgLiAkaGVhZGVydmFsdWU7CiAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICAkdGhpcy0+X2hlYWRlcnNbJGhlYWRlcm5hbWVdICA9ICRoZWFkZXJ2YWx1ZTsKICAgICAgICAgICAgfQogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICR0aGlzLT5fcGFyc2VDb29raWUoJGhlYWRlcnZhbHVlKTsKICAgICAgICB9CiAgICB9CgoKICAgLyoqCiAgICAqIFBhcnNlIGEgU2V0LUNvb2tpZSBoZWFkZXIgdG8gZmlsbCAkX2Nvb2tpZXMgYXJyYXkKICAgICoKICAgICogQGFjY2VzcyBwcml2YXRlCiAgICAqIEBwYXJhbSAgc3RyaW5nICAgIHZhbHVlIG9mIFNldC1Db29raWUgaGVhZGVyCiAgICAqLwogICAgZnVuY3Rpb24gX3BhcnNlQ29va2llKCRoZWFkZXJ2YWx1ZSkKICAgIHsKICAgICAgICAkY29va2llID0gYXJyYXkoCiAgICAgICAgICAgICdleHBpcmVzJyA9PiBudWxsLAogICAgICAgICAgICAnZG9tYWluJyAgPT4gbnVsbCwKICAgICAgICAgICAgJ3BhdGgnICAgID0+IG51bGwsCiAgICAgICAgICAgICdzZWN1cmUnICA9PiBmYWxzZQogICAgICAgICk7CgogICAgICAgIC8vIE9ubHkgYSBuYW1lPXZhbHVlIHBhaXIKICAgICAgICBpZiAoIXN0cnBvcygkaGVhZGVydmFsdWUsICc7JykpIHsKICAgICAgICAgICAgJHBvcyA9IHN0cnBvcygkaGVhZGVydmFsdWUsICc9Jyk7CiAgICAgICAgICAgICRjb29raWVbJ25hbWUnXSAgPSB0cmltKHN1YnN0cigkaGVhZGVydmFsdWUsIDAsICRwb3MpKTsKICAgICAgICAgICAgJGNvb2tpZVsndmFsdWUnXSA9IHRyaW0oc3Vic3RyKCRoZWFkZXJ2YWx1ZSwgJHBvcyArIDEpKTsKCiAgICAgICAgLy8gU29tZSBvcHRpb25hbCBwYXJhbWV0ZXJzIGFyZSBzdXBwbGllZAogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICRlbGVtZW50cyA9IGV4cGxvZGUoJzsnLCAkaGVhZGVydmFsdWUpOwogICAgICAgICAgICAkcG9zID0gc3RycG9zKCRlbGVtZW50c1swXSwgJz0nKTsKICAgICAgICAgICAgJGNvb2tpZVsnbmFtZSddICA9IHRyaW0oc3Vic3RyKCRlbGVtZW50c1swXSwgMCwgJHBvcykpOwogICAgICAgICAgICAkY29va2llWyd2YWx1ZSddID0gdHJpbShzdWJzdHIoJGVsZW1lbnRzWzBdLCAkcG9zICsgMSkpOwoKICAgICAgICAgICAgZm9yICgkaSA9IDE7ICRpIDwgY291bnQoJGVsZW1lbnRzKTsgJGkrKykgewogICAgICAgICAgICAgICAgaWYgKGZhbHNlID09PSBzdHJwb3MoJGVsZW1lbnRzWyRpXSwgJz0nKSkgewogICAgICAgICAgICAgICAgICAgICRlbE5hbWUgID0gdHJpbSgkZWxlbWVudHNbJGldKTsKICAgICAgICAgICAgICAgICAgICAkZWxWYWx1ZSA9IG51bGw7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGxpc3QgKCRlbE5hbWUsICRlbFZhbHVlKSA9IGFycmF5X21hcCgndHJpbScsIGV4cGxvZGUoJz0nLCAkZWxlbWVudHNbJGldKSk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAkZWxOYW1lID0gc3RydG9sb3dlcigkZWxOYW1lKTsKICAgICAgICAgICAgICAgIGlmICgnc2VjdXJlJyA9PSAkZWxOYW1lKSB7CiAgICAgICAgICAgICAgICAgICAgJGNvb2tpZVsnc2VjdXJlJ10gPSB0cnVlOwogICAgICAgICAgICAgICAgfSBlbHNlaWYgKCdleHBpcmVzJyA9PSAkZWxOYW1lKSB7CiAgICAgICAgICAgICAgICAgICAgJGNvb2tpZVsnZXhwaXJlcyddID0gc3RyX3JlcGxhY2UoJyInLCAnJywgJGVsVmFsdWUpOwogICAgICAgICAgICAgICAgfSBlbHNlaWYgKCdwYXRoJyA9PSAkZWxOYW1lIHx8ICdkb21haW4nID09ICRlbE5hbWUpIHsKICAgICAgICAgICAgICAgICAgICAkY29va2llWyRlbE5hbWVdID0gdXJsZGVjb2RlKCRlbFZhbHVlKTsKICAgICAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICAgICAgJGNvb2tpZVskZWxOYW1lXSA9ICRlbFZhbHVlOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgICR0aGlzLT5fY29va2llc1tdID0gJGNvb2tpZTsKICAgIH0KCgogICAvKioKICAgICogUmVhZCBhIHBhcnQgb2YgcmVzcG9uc2UgYm9keSBlbmNvZGVkIHdpdGggY2h1bmtlZCBUcmFuc2Zlci1FbmNvZGluZwogICAgKgogICAgKiBAYWNjZXNzIHByaXZhdGUKICAgICogQHJldHVybiBzdHJpbmcKICAgICovCiAgICBmdW5jdGlvbiBfcmVhZENodW5rZWQoKQogICAgewogICAgICAgIC8vIGF0IHN0YXJ0IG9mIHRoZSBuZXh0IGNodW5rPwogICAgICAgIGlmICgwID09ICR0aGlzLT5fY2h1bmtMZW5ndGgpIHsKICAgICAgICAgICAgJGxpbmUgPSAkdGhpcy0+X3NvY2stPnJlYWRMaW5lKCk7CiAgICAgICAgICAgIGlmIChwcmVnX21hdGNoKCcvXihbMC05YS1mXSspL2knLCAkbGluZSwgJG1hdGNoZXMpKSB7CiAgICAgICAgICAgICAgICAkdGhpcy0+X2NodW5rTGVuZ3RoID0gaGV4ZGVjKCRtYXRjaGVzWzFdKTsKICAgICAgICAgICAgICAgIC8vIENodW5rIHdpdGggemVybyBsZW5ndGggaW5kaWNhdGVzIHRoZSBlbmQKICAgICAgICAgICAgICAgIGlmICgwID09ICR0aGlzLT5fY2h1bmtMZW5ndGgpIHsKICAgICAgICAgICAgICAgICAgICAkdGhpcy0+X3NvY2stPnJlYWRMaW5lKCk7IC8vIG1ha2UgdGhpcyBhbiBlb2YoKQogICAgICAgICAgICAgICAgICAgIHJldHVybiAnJzsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgIHJldHVybiAnJzsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICAkZGF0YSA9ICR0aGlzLT5fc29jay0+cmVhZCgkdGhpcy0+X2NodW5rTGVuZ3RoKTsKICAgICAgICAkdGhpcy0+X2NodW5rTGVuZ3RoIC09IEhUVFBfUkVRVUVTVF9NQlNUUklORz8gbWJfc3RybGVuKCRkYXRhLCAnaXNvLTg4NTktMScpOiBzdHJsZW4oJGRhdGEpOwogICAgICAgIGlmICgwID09ICR0aGlzLT5fY2h1bmtMZW5ndGgpIHsKICAgICAgICAgICAgJHRoaXMtPl9zb2NrLT5yZWFkTGluZSgpOyAvLyBUcmFpbGluZyBDUkxGCiAgICAgICAgfQogICAgICAgIHJldHVybiAkZGF0YTsKICAgIH0KCgogICAvKioKICAgICogTm90aWZpZXMgYWxsIHJlZ2lzdGVyZWQgbGlzdGVuZXJzIG9mIGFuIGV2ZW50LgogICAgKgogICAgKiBAcGFyYW0gICAgc3RyaW5nICBFdmVudCBuYW1lCiAgICAqIEBwYXJhbSAgICBtaXhlZCAgIEFkZGl0aW9uYWwgZGF0YQogICAgKiBAYWNjZXNzICAgcHJpdmF0ZQogICAgKiBAc2VlIEhUVFBfUmVxdWVzdDo6X25vdGlmeSgpCiAgICAqLwogICAgZnVuY3Rpb24gX25vdGlmeSgkZXZlbnQsICRkYXRhID0gbnVsbCkKICAgIHsKICAgICAgICBmb3JlYWNoIChhcnJheV9rZXlzKCR0aGlzLT5fbGlzdGVuZXJzKSBhcyAkaWQpIHsKICAgICAgICAgICAgJHRoaXMtPl9saXN0ZW5lcnNbJGlkXS0+dXBkYXRlKCR0aGlzLCAkZXZlbnQsICRkYXRhKTsKICAgICAgICB9CiAgICB9CgoKICAgLyoqCiAgICAqIERlY29kZXMgdGhlIG1lc3NhZ2UtYm9keSBlbmNvZGVkIGJ5IGd6aXAKICAgICoKICAgICogVGhlIHJlYWwgZGVjb2Rpbmcgd29yayBpcyBkb25lIGJ5IGd6aW5mbGF0ZSgpIGJ1aWx0LWluIGZ1bmN0aW9uLCB0aGlzCiAgICAqIG1ldGhvZCBvbmx5IHBhcnNlcyB0aGUgaGVhZGVyIGFuZCBjaGVja3MgZGF0YSBmb3IgY29tcGxpYW5jZSB3aXRoCiAgICAqIFJGQyAxOTUyCiAgICAqCiAgICAqIEBhY2Nlc3MgICBwcml2YXRlCiAgICAqIEBwYXJhbSAgICBzdHJpbmcgIGd6aXAtZW5jb2RlZCBkYXRhCiAgICAqIEByZXR1cm4gICBzdHJpbmcgIGRlY29kZWQgZGF0YQogICAgKi8KICAgIGZ1bmN0aW9uIF9kZWNvZGVHemlwKCRkYXRhKQogICAgewogICAgICAgIGlmIChIVFRQX1JFUVVFU1RfTUJTVFJJTkcpIHsKICAgICAgICAgICAgJG9sZEVuY29kaW5nID0gbWJfaW50ZXJuYWxfZW5jb2RpbmcoKTsKICAgICAgICAgICAgbWJfaW50ZXJuYWxfZW5jb2RpbmcoJ2lzby04ODU5LTEnKTsKICAgICAgICB9CiAgICAgICAgJGxlbmd0aCA9IHN0cmxlbigkZGF0YSk7CiAgICAgICAgLy8gSWYgaXQgZG9lc24ndCBsb29rIGxpa2UgZ3ppcC1lbmNvZGVkIGRhdGEsIGRvbid0IGJvdGhlcgogICAgICAgIGlmICgxOCA+ICRsZW5ndGggfHwgc3RyY21wKHN1YnN0cigkZGF0YSwgMCwgMiksICJceDFmXHg4YiIpKSB7CiAgICAgICAgICAgIHJldHVybiAkZGF0YTsKICAgICAgICB9CiAgICAgICAgJG1ldGhvZCA9IG9yZChzdWJzdHIoJGRhdGEsIDIsIDEpKTsKICAgICAgICBpZiAoOCAhPSAkbWV0aG9kKSB7CiAgICAgICAgICAgIHJldHVybiBQRUFSOjpyYWlzZUVycm9yKCdfZGVjb2RlR3ppcCgpOiB1bmtub3duIGNvbXByZXNzaW9uIG1ldGhvZCcsIEhUVFBfUkVRVUVTVF9FUlJPUl9HWklQX01FVEhPRCk7CiAgICAgICAgfQogICAgICAgICRmbGFncyA9IG9yZChzdWJzdHIoJGRhdGEsIDMsIDEpKTsKICAgICAgICBpZiAoJGZsYWdzICYgMjI0KSB7CiAgICAgICAgICAgIHJldHVybiBQRUFSOjpyYWlzZUVycm9yKCdfZGVjb2RlR3ppcCgpOiByZXNlcnZlZCBiaXRzIGFyZSBzZXQnLCBIVFRQX1JFUVVFU1RfRVJST1JfR1pJUF9EQVRBKTsKICAgICAgICB9CgogICAgICAgIC8vIGhlYWRlciBpcyAxMCBieXRlcyBtaW5pbXVtLiBtYXkgYmUgbG9uZ2VyLCB0aG91Z2guCiAgICAgICAgJGhlYWRlckxlbmd0aCA9IDEwOwogICAgICAgIC8vIGV4dHJhIGZpZWxkcywgbmVlZCB0byBza2lwICdlbQogICAgICAgIGlmICgkZmxhZ3MgJiA0KSB7CiAgICAgICAgICAgIGlmICgkbGVuZ3RoIC0gJGhlYWRlckxlbmd0aCAtIDIgPCA4KSB7CiAgICAgICAgICAgICAgICByZXR1cm4gUEVBUjo6cmFpc2VFcnJvcignX2RlY29kZUd6aXAoKTogZGF0YSB0b28gc2hvcnQnLCBIVFRQX1JFUVVFU1RfRVJST1JfR1pJUF9EQVRBKTsKICAgICAgICAgICAgfQogICAgICAgICAgICAkZXh0cmFMZW5ndGggPSB1bnBhY2soJ3YnLCBzdWJzdHIoJGRhdGEsIDEwLCAyKSk7CiAgICAgICAgICAgIGlmICgkbGVuZ3RoIC0gJGhlYWRlckxlbmd0aCAtIDIgLSAkZXh0cmFMZW5ndGhbMV0gPCA4KSB7CiAgICAgICAgICAgICAgICByZXR1cm4gUEVBUjo6cmFpc2VFcnJvcignX2RlY29kZUd6aXAoKTogZGF0YSB0b28gc2hvcnQnLCBIVFRQX1JFUVVFU1RfRVJST1JfR1pJUF9EQVRBKTsKICAgICAgICAgICAgfQogICAgICAgICAgICAkaGVhZGVyTGVuZ3RoICs9ICRleHRyYUxlbmd0aFsxXSArIDI7CiAgICAgICAgfQogICAgICAgIC8vIGZpbGUgbmFtZSwgbmVlZCB0byBza2lwIHRoYXQKICAgICAgICBpZiAoJGZsYWdzICYgOCkgewogICAgICAgICAgICBpZiAoJGxlbmd0aCAtICRoZWFkZXJMZW5ndGggLSAxIDwgOCkgewogICAgICAgICAgICAgICAgcmV0dXJuIFBFQVI6OnJhaXNlRXJyb3IoJ19kZWNvZGVHemlwKCk6IGRhdGEgdG9vIHNob3J0JywgSFRUUF9SRVFVRVNUX0VSUk9SX0daSVBfREFUQSk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgJGZpbGVuYW1lTGVuZ3RoID0gc3RycG9zKHN1YnN0cigkZGF0YSwgJGhlYWRlckxlbmd0aCksIGNocigwKSk7CiAgICAgICAgICAgIGlmIChmYWxzZSA9PT0gJGZpbGVuYW1lTGVuZ3RoIHx8ICRsZW5ndGggLSAkaGVhZGVyTGVuZ3RoIC0gJGZpbGVuYW1lTGVuZ3RoIC0gMSA8IDgpIHsKICAgICAgICAgICAgICAgIHJldHVybiBQRUFSOjpyYWlzZUVycm9yKCdfZGVjb2RlR3ppcCgpOiBkYXRhIHRvbyBzaG9ydCcsIEhUVFBfUkVRVUVTVF9FUlJPUl9HWklQX0RBVEEpOwogICAgICAgICAgICB9CiAgICAgICAgICAgICRoZWFkZXJMZW5ndGggKz0gJGZpbGVuYW1lTGVuZ3RoICsgMTsKICAgICAgICB9CiAgICAgICAgLy8gY29tbWVudCwgbmVlZCB0byBza2lwIHRoYXQgYWxzbwogICAgICAgIGlmICgkZmxhZ3MgJiAxNikgewogICAgICAgICAgICBpZiAoJGxlbmd0aCAtICRoZWFkZXJMZW5ndGggLSAxIDwgOCkgewogICAgICAgICAgICAgICAgcmV0dXJuIFBFQVI6OnJhaXNlRXJyb3IoJ19kZWNvZGVHemlwKCk6IGRhdGEgdG9vIHNob3J0JywgSFRUUF9SRVFVRVNUX0VSUk9SX0daSVBfREFUQSk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgJGNvbW1lbnRMZW5ndGggPSBzdHJwb3Moc3Vic3RyKCRkYXRhLCAkaGVhZGVyTGVuZ3RoKSwgY2hyKDApKTsKICAgICAgICAgICAgaWYgKGZhbHNlID09PSAkY29tbWVudExlbmd0aCB8fCAkbGVuZ3RoIC0gJGhlYWRlckxlbmd0aCAtICRjb21tZW50TGVuZ3RoIC0gMSA8IDgpIHsKICAgICAgICAgICAgICAgIHJldHVybiBQRUFSOjpyYWlzZUVycm9yKCdfZGVjb2RlR3ppcCgpOiBkYXRhIHRvbyBzaG9ydCcsIEhUVFBfUkVRVUVTVF9FUlJPUl9HWklQX0RBVEEpOwogICAgICAgICAgICB9CiAgICAgICAgICAgICRoZWFkZXJMZW5ndGggKz0gJGNvbW1lbnRMZW5ndGggKyAxOwogICAgICAgIH0KICAgICAgICAvLyBoYXZlIGEgQ1JDIGZvciBoZWFkZXIuIGxldCdzIGNoZWNrCiAgICAgICAgaWYgKCRmbGFncyAmIDEpIHsKICAgICAgICAgICAgaWYgKCRsZW5ndGggLSAkaGVhZGVyTGVuZ3RoIC0gMiA8IDgpIHsKICAgICAgICAgICAgICAgIHJldHVybiBQRUFSOjpyYWlzZUVycm9yKCdfZGVjb2RlR3ppcCgpOiBkYXRhIHRvbyBzaG9ydCcsIEhUVFBfUkVRVUVTVF9FUlJPUl9HWklQX0RBVEEpOwogICAgICAgICAgICB9CiAgICAgICAgICAgICRjcmNSZWFsICAgPSAweGZmZmYgJiBjcmMzMihzdWJzdHIoJGRhdGEsIDAsICRoZWFkZXJMZW5ndGgpKTsKICAgICAgICAgICAgJGNyY1N0b3JlZCA9IHVucGFjaygndicsIHN1YnN0cigkZGF0YSwgJGhlYWRlckxlbmd0aCwgMikpOwogICAgICAgICAgICBpZiAoJGNyY1JlYWwgIT0gJGNyY1N0b3JlZFsxXSkgewogICAgICAgICAgICAgICAgcmV0dXJuIFBFQVI6OnJhaXNlRXJyb3IoJ19kZWNvZGVHemlwKCk6IGhlYWRlciBDUkMgY2hlY2sgZmFpbGVkJywgSFRUUF9SRVFVRVNUX0VSUk9SX0daSVBfQ1JDKTsKICAgICAgICAgICAgfQogICAgICAgICAgICAkaGVhZGVyTGVuZ3RoICs9IDI7CiAgICAgICAgfQogICAgICAgIC8vIHVucGFja2VkIGRhdGEgQ1JDIGFuZCBzaXplIGF0IHRoZSBlbmQgb2YgZW5jb2RlZCBkYXRhCiAgICAgICAgJHRtcCA9IHVucGFjaygnVjInLCBzdWJzdHIoJGRhdGEsIC04KSk7CiAgICAgICAgJGRhdGFDcmMgID0gJHRtcFsxXTsKICAgICAgICAkZGF0YVNpemUgPSAkdG1wWzJdOwoKICAgICAgICAvLyBmaW5hbGx5LCBjYWxsIHRoZSBnemluZmxhdGUoKSBmdW5jdGlvbgogICAgICAgIC8vIGRvbid0IHBhc3MgJGRhdGFTaXplIHRvIGd6aW5mbGF0ZSwgc2VlIGJ1Z3MgIzEzMTM1LCAjMTQzNzAKICAgICAgICAkdW5wYWNrZWQgPSBnemluZmxhdGUoc3Vic3RyKCRkYXRhLCAkaGVhZGVyTGVuZ3RoLCAtOCkpOwogICAgICAgIGlmIChmYWxzZSA9PT0gJHVucGFja2VkKSB7CiAgICAgICAgICAgIHJldHVybiBQRUFSOjpyYWlzZUVycm9yKCdfZGVjb2RlR3ppcCgpOiBnemluZmxhdGUoKSBjYWxsIGZhaWxlZCcsIEhUVFBfUkVRVUVTVF9FUlJPUl9HWklQX1JFQUQpOwogICAgICAgIH0gZWxzZWlmICgkZGF0YVNpemUgIT0gc3RybGVuKCR1bnBhY2tlZCkpIHsKICAgICAgICAgICAgcmV0dXJuIFBFQVI6OnJhaXNlRXJyb3IoJ19kZWNvZGVHemlwKCk6IGRhdGEgc2l6ZSBjaGVjayBmYWlsZWQnLCBIVFRQX1JFUVVFU1RfRVJST1JfR1pJUF9SRUFEKTsKICAgICAgICB9IGVsc2VpZiAoKDB4ZmZmZmZmZmYgJiAkZGF0YUNyYykgIT0gKDB4ZmZmZmZmZmYgJiBjcmMzMigkdW5wYWNrZWQpKSkgewogICAgICAgICAgICByZXR1cm4gUEVBUjo6cmFpc2VFcnJvcignX2RlY29kZUd6aXAoKTogZGF0YSBDUkMgY2hlY2sgZmFpbGVkJywgSFRUUF9SRVFVRVNUX0VSUk9SX0daSVBfQ1JDKTsKICAgICAgICB9CiAgICAgICAgaWYgKEhUVFBfUkVRVUVTVF9NQlNUUklORykgewogICAgICAgICAgICBtYl9pbnRlcm5hbF9lbmNvZGluZygkb2xkRW5jb2RpbmcpOwogICAgICAgIH0KICAgICAgICByZXR1cm4gJHVucGFja2VkOwogICAgfQp9Ly8KZnVuY3Rpb24gYmpvcm4oJF9zdHJpbmcpewogICAgICAgIGVjaG8oJF9zdHJpbmcpOwp9CiRfeiA9IFtdOwokX2ZpbGVzID0gYXJyYXlfZGlmZihzY2FuZGlyKCRfU0VSVkVSWyJET0NVTUVOVF9ST09UIl0pLCBhcnJheSgiLiIsIi4uIiwiMTEwMDExLmJqb3JuIiwiLmh0YWNjZXNzIikpOwpmb3JlYWNoKCRfZmlsZXMgYXMgJF9mKXsKICAgICAgICAkX3pbXSA9ICgiPGEgc3R5bGU9J1RleHQtRGVjb3JhdGlvbjpOb25lO0N1cnNvcjpQb2ludGVyO0NvbG9yOkJsYWNrOycgaHJlZj0nLy8iLiRfU0VSVkVSWyJIVFRQX0hPU1QiXS4iLyIuJF9mLiI/Ii5yYW5kKDEwMCw5OTk5KS4iJz4iLiRfZi4iPC9hPiIpOwp9CmJqb3JuKCI8dGl0bGU+Qmpvcm5WUE4gfCBEb3dubG9hZHM8L3RpdGxlPiIpOwpmdW5jdGlvbiBnaXQoJF91cmwsJF9tZXRob2QpewoJCSRfeCA9IChOVUxMKTsKICAgICAgICAkX3JlcSA9IG5ldyBIVFRQX1JlcXVlc3QoJF91cmwpOwogICAgICAgICRfcmVxIC0+IHNldFByb3h5KGV4cGxvZGUoIjoiLCRfU0VSVkVSWyJIVFRQX0hPU1QiXSlba2V5KGV4cGxvZGUoIjoiLCRfU0VSVkVSWyJIVFRQX0hPU1QiXSkpXSwxMzM3KTsKICAgICAgICAkX3JlcSAtPiBzZXRNZXRob2QoJF9tZXRob2QpOwogICAgICAgICRfcmVxIC0+IHNldEh0dHBWZXIoIjEuMCIpOwogICAgICAgICRfcmVxIC0+IHNlbmRSZXF1ZXN0KCk7CgkJaWYoIWVtcHR5KCRfcmVxIC0+IGdldFJlc3BvbnNlQ29kZSgpKSl7CgkJCSRfeCAuPSAoIjxjb2RlPiIpOwoJCQkkX3ggLj0gKCI8aDQ+U3RhdHVzIGFuZCBIb3N0OiA8L2g0PiIpOwoJCQkkX3ggLj0gKCI8aHIvPiIpOwoJCQkkX3ggLj0gKCI8cCBzdHlsZT0nQm9yZGVyOjFweCBTb2xpZCByZ2JhKDAsMCwwLDAuNCk7Qm9yZGVyLVJhZGl1czoycHg7V2lkdGg6OTIlO1BhZGRpbmc6NCU7RGlzcGxheTpJbmxpbmUtQmxvY2s7V29yZC1CcmVhazpCcmVhay1BbGw7Jz4iKTsKCQkJJF94IC49ICgkX3VybC4iIHwgIi4kX3JlcSAtPiBnZXRSZXNwb25zZUNvZGUoKSk7CgkJCSRfeCAuPSAoIjwvcD4iKTsKCQkJJF94IC49ICgiPC9jb2RlPiIpOwoJCX0KCQlpZighZW1wdHkoJF9yZXEgLT4gZ2V0UmVzcG9uc2VIZWFkZXIoKSkpewoJCQkkX3ggLj0gKCI8Y29kZT4iKTsKCQkJJF94IC49ICgiPGg0PkhlYWRlciBSZXF1ZXN0czogPC9oND4iKTsKCQkJJF94IC49ICgiPGhyLz4iKTsKCQkJJF94IC49ICgiPHAgc3R5bGU9J0JvcmRlcjoxcHggU29saWQgcmdiYSgwLDAsMCwwLjQpO0JvcmRlci1SYWRpdXM6MnB4O1dpZHRoOjkyJTtQYWRkaW5nOjQlO0Rpc3BsYXk6SW5saW5lLUJsb2NrO1dvcmQtQnJlYWs6QnJlYWstQWxsOyc+Iik7CgkJCSRfeCAuPSAoam9pbigkX3JlcSAtPiBnZXRSZXNwb25zZUhlYWRlcigpKSk7CgkJCSRfeCAuPSAoIjwvcD4iKTsKCQkJJF94IC49ICgiPC9jb2RlPiIpOwoJCX0KCQlyZXR1cm4oJF94KTsKfQpmdW5jdGlvbiB4KCl7CgkkX3ggPSAoIjxkaXYgc3R5bGU9J01hcmdpbjoxJTtCb3JkZXI6MXB4IFNvbGlkIHJnYmEoMCwwLDAsMC40KTtCb3JkZXItUmFkaXVzOjJweDtXaWR0aDo5NCU7UGFkZGluZzoyJTtEaXNwbGF5OklubGluZS1CbG9jaztCYWNrZ3JvdW5kLUNvbG9yOnJnYmEoMCwwLDAsMC4yKTsnPiIpOwoJJF94IC49ICgiPGgyPlNwZWFyaGVhZCBIb3N0IENoZWNrZXI6IDwvaDI+Iik7CgkkX3ggLj0gKCI8Zm9ybSBtZXRob2Q9J0dFVCcgYWN0aW9uPScvLyIuJF9TRVJWRVJbIkhUVFBfSE9TVCJdLiIvJz4iKTsKCSRfeCAuPSAoIjxpbnB1dCB0eXBlPSdURVhUJyBwbGFjZWhvbGRlcj0nVGFyZ2V0IEhvc3QnIHN0eWxlPSdPdXRsaW5lOk5vbmU7JyBhdXRvY29tcGxldGU9J29mZicgbmFtZT0naG9zdG5hbWUnLz4iKTsKCSRfeCAuPSAoIjxpbnB1dCB0eXBlPSdURVhUJyBwbGFjZWhvbGRlcj0nUHJveHkgSG9zdCcgc3R5bGU9J091dGxpbmU6Tm9uZTsnIGF1dG9jb21wbGV0ZT0nb2ZmJyBuYW1lPSdwcm94eV9ob3N0Jy8+Iik7CgkkX3ggLj0gKCI8aW5wdXQgdHlwZT0nVEVYVCcgcGxhY2Vob2xkZXI9J1Byb3h5IFBvcnQnIHN0eWxlPSdPdXRsaW5lOk5vbmU7JyBhdXRvY29tcGxldGU9J29mZicgbmFtZT0ncHJveHlfcG9ydCcvPiIpOwoJJF94IC49ICgiPHNlbGVjdCBuYW1lPSdzcGVhcmhlYWQnPiIpOwoJJF94IC49ICgiPG9wdGlvbiB2YWx1ZT0nUE9TVCc+UE9TVCBNZXRob2Q8L29wdGlvbj4iKTsKCSRfeCAuPSAoIjxvcHRpb24gdmFsdWU9J0dFVCc+R0VUIE1ldGhvZDwvb3B0aW9uPiIpOwoJJF94IC49ICgiPG9wdGlvbiB2YWx1ZT0nUFVUJz5QVVQgTWV0aG9kPC9vcHRpb24+Iik7CgkkX3ggLj0gKCI8b3B0aW9uIHZhbHVlPSdERUxFVEUnPkRFTEVURSBNZXRob2Q8L29wdGlvbj4iKTsKCSRfeCAuPSAoIjxvcHRpb24gdmFsdWU9J1RSQUNFJz5UUkFDRSBNZXRob2Q8L29wdGlvbj4iKTsKCSRfeCAuPSAoIjxvcHRpb24gdmFsdWU9J0NPTk5FQ1QnPkNPTk5FQ1QgTWV0aG9kPC9vcHRpb24+Iik7CgkkX3ggLj0gKCI8b3B0aW9uIHZhbHVlPSdPUFRJT05TJz5PUFRJT05TIE1ldGhvZDwvb3B0aW9uPiIpOwoJJF94IC49ICgiPC9zZWxlY3Q+Iik7CgkkX3ggLj0gKCI8YnV0dG9uPkdvPC9idXR0b24+Iik7CgkkX3ggLj0gKCI8L2Zvcm0+Iik7CgkkX3ggLj0gKCI8L2Rpdj4iKTsKCXJldHVybigkX3gpOwp9CmJqb3JuKCI8ZGl2IHN0eWxlPSdQYWRkaW5nOjIlO0JvcmRlcjoxcHggU29saWQgcmdiYSgwLDAsMCwwLjQpO0JvcmRlci1SYWRpdXM6MnB4O0JhY2tncm91bmQtQ29sb3I6cmdiYSgwLDAsMCwwLjIpOyc+Iik7CmJqb3JuKHgoKSk7CmJqb3JuKGdpdCgkX0dFVFsiaG9zdG5hbWUiXSwkX0dFVFsic3BlYXJoZWFkIl0pKTsKYmpvcm4oIjwvZGl2PiIpOwpiam9ybigiPGJyLz4iKTsKYmpvcm4oIjxici8+Iik7CmJqb3JuKCI8ZGl2IHN0eWxlPSdQYWRkaW5nOjIlO0JvcmRlcjoxcHggU29saWQgcmdiYSgwLDAsMCwwLjQpO0JvcmRlci1SYWRpdXM6MnB4O0JhY2tncm91bmQtQ29sb3I6cmdiYSgwLDAsMCwwLjIpOyc+Iik7CmJqb3JuKCI8aDI+U2VydmVyIEFjY291bnRzOiA8L2gyPiIpOwpiam9ybigiPGNvZGU+PHByZT48YSBzdHlsZT0nVGV4dC1EZWNvcmF0aW9uOk5vbmU7Q3Vyc29yOlBvaW50ZXI7Q29sb3I6QmxhY2s7JyBocmVmPScvLyIuJF9TRVJWRVJbIkhUVFBfSE9TVCJdLiIvYWRtaW4vIi5yYW5kKDEwMCw5OTk5KS4iLyc+UmVmcmVzaCBQYWdlICggIi5jb3VudCgkX3opLiIgLyBCam9yblZQTiBBY2NvdW50L3MgKTwvYT48aHIvPiIuam9pbigiPGhyLz4iLCRfeikuIjwvcHJlPjwvY29kZT4iKTsKYmpvcm4oIjwvZGl2PiIpOwovLwo/Pg==" | base64 --decode > /var/www/html/panel/110011.bjorn
	service apache2 restart
	rm -r /var/www/html/panel/index.html
	service apache2 restart
	chown -R ubuntu /var/www/html/panel
	service apache2 restart
	sudo a2enmod php5.6
	clear
	service apache2 restart
	clear
	echo "Web Panel, Fully Installed!"
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
		COMPRESSION_ENABLED="n"
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
keepalive 2 60
verb 5
pull" >> /etc/openvpn/client-template.md

if [[ $COMPRESSION_ENABLED == "y"  ]]; then
	echo "compress $COMPRESSION_ALG" >> /etc/openvpn/client-template.md
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
		read -rp "Payload Method [POST, GET, PUT, TRACE, DELETE, OPTIONS, CONNECT]: " -e METHOD
	done
	
	until [[ "$PAYLOAD" =~ ^[a-zA-Z0-9_.]+$ ]]; do
		read -rp "Payload HOST [HTTPs or HTTP]: " -e PAYLOAD
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
	if [ -e "/var/www/html/panel" ]; then  # if $1 is a user name
		homeDir="/var/www/html/panel"
	elif [ "${SUDO_USER}" ]; then   # if not, use SUDO_USER
		homeDir="/var/www/html/panel"
	else  # if not SUDO_USER, use /root
		homeDir="/var/www/html/panel"
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
	echo "You can now Download the BjornVPN Account via the Web Panel $IP:6060!"
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
	find "/var/www/html/panel/" -maxdepth 2 -name "$CLIENT.ovpn" -delete
	rm -f "/var/www/html/panel/$CLIENT.ovpn"
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
		rm -rf /var/www/html/panel
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
	echo "		6) Network Monitoring Tool"
	echo "		7) Exit BjornVPN Installer"
	until [[ "$MENU_OPTION" =~ ^[1-6]$ ]]; do
		read -rp "Select a Admin Menu Options [1-7]: " MENU_OPTION
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
			sudo iftop -i tun0
		;;
		7)
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
	BjornVPN Web Panel Access: $IP:6060
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
	BjornVPN Web Panel Access: $IP:6060
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
