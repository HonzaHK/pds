SOURCE="pds-spoof.cpp pds_addr.cpp pds_pkt.cpp"
EXECUTABLE="pds-spoof"
FLAGS="-g -std=c++11 -Wall -Wextra -pedantic"
LIB_PCAP="-lpcap"

INTERFACE="wlp3s0"
SPOOF_INTERVAL_MS="1000"
PROTOCOL="arp"

#--------------------------------------------
IP_LIBRA_UB="192.168.0.101"
IP6_LIBRA_IB="fe80::21b:9eff:fe8a:8696"
MAC_LIBRA_UB="001b.9e8a.8696"

IP_MATKA="192.168.0.104"
IP6_MATKA="fe80::406d:9ecd:4460:c347"
MAC_MATKA="3402.86cc.3553"
#--------------------------------------------


IP1=$IP_LIBRA_UB
MAC1=$MAC_LIBRA_UB
IP2=$IP_MATKA
MAC2=$MAC_MATKA

if [ -f $EXECUTABLE ]; then
	sudo rm $EXECUTABLE
fi

echo "-- COMPILATION ----------------------------------------"
g++ $FLAGS $SOURCE -o $EXECUTABLE $LIB_PCAP
echo "-------------------------------------------------------"

if [ -f $EXECUTABLE ]; then
	sudo valgrind --leak-check=full ./$EXECUTABLE -i $INTERFACE -t $SPOOF_INTERVAL_MS -p $PROTOCOL -victim1ip $IP1 -victim1mac $MAC1 -victim2ip $IP2 -victim2mac $MAC2
fi