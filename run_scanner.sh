SOURCE="pds-scanner.cpp pds_addr.cpp pds_pkt.cpp"
EXECUTABLE="pds-scanner"
FLAGS="-std=c++11 -Wall -Wextra -pedantic"
OUTFILE="detected-devices.xml"
INTERFACE="wlp3s0"
LIB_PCAP="-lpcap"

if [ -f $EXECUTABLE ]; then
	sudo rm $EXECUTABLE
fi
if [ -f $OUTFILE ]; then
	sudo rm $OUTFILE
fi

echo "-- COMPILATION ----------------------------------------"
g++ $FLAGS $SOURCE -o $EXECUTABLE $LIB_PCAP
echo "-------------------------------------------------------"

if [ -f $EXECUTABLE ]; then
sudo ./$EXECUTABLE -i $INTERFACE -f $OUTFILE
fi