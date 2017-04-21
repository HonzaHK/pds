SOURCE="pds-scanner.cpp pds_addr.cpp pds_pkt.cpp pds_host.cpp"
EXECUTABLE="pds-scanner"
FLAGS="-std=c++11 -Wall -Wextra -pedantic"
OUTFILE="detected-devices.xml"
INTERFACE="wlp3s0"
LIB_PCAP="-lpcap"
LIB_XML="-I/usr/include/libxml2 -lxml2"

if [ -f $EXECUTABLE ]; then
	sudo rm $EXECUTABLE
fi
if [ -f $OUTFILE ]; then
	sudo rm $OUTFILE
fi

echo "-- COMPILATION ----------------------------------------"
g++ $FLAGS $SOURCE -o $EXECUTABLE $LIB_PCAP $LIB_XML
echo "-------------------------------------------------------"

if [ -f $EXECUTABLE ]; then
sudo ./$EXECUTABLE -i $INTERFACE -f $OUTFILE
fi