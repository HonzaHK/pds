SOURCE="pds-spoof.cpp pds_addr.cpp pds_pkt.cpp"
EXECUTABLE="pds-spoof"
FLAGS="-std=c++11 -Wall -Wextra -pedantic"
LIB_PCAP="-lpcap"

INTERFACE="wlp3s0"
SPOOF_INTERVAL_MS="1000"
PROTOCOL="arp"

IP_LIBRA_BR="192.168.0.249"
MAC_LIBRA_BR="0019.d2c1.93ab"

IP_LIBRA_UB="192.168.0.101"
MAC_LIBRA_UB="001b.9e8a.8696"

IP2="192.168.0.111"
MAC2="dddd.eeee.ffff"

IP1=$IP_LIBRA_UB
MAC1=$MAC_LIBRA_UB

if [ -f $EXECUTABLE ]; then
	sudo rm $EXECUTABLE
fi

echo "-- COMPILATION ----------------------------------------"
g++ $FLAGS $SOURCE -o $EXECUTABLE $LIB_PCAP
echo "-------------------------------------------------------"

if [ -f $EXECUTABLE ]; then
	sudo ./$EXECUTABLE -i $INTERFACE -t $SPOOF_INTERVAL_MS -p $PROTOCOL -victim1ip $IP1 -victim1mac $MAC1 -victim2ip $IP2 -victim2mac $MAC2
fi