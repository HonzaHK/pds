SOURCE="pds-scanner.cpp"
EXECUTABLE="pds-scanner"
FLAGS="-std=c++11 -Wall -Wextra -pedantic"
OUTFILE="scanner_out.xml"
INTERFACE="kkkkkkkk"
LIB_PCAP="-lpcap"

if [ -f $EXECUTABLE ]; then
	rm $EXECUTABLE
fi
if [ -f $OUTFILE ]; then
	rm $OUTFILE
fi

echo "-- COMPILATION ----------------------------------------"
g++ $FLAGS $SOURCE -o $EXECUTABLE $LIB_PCAP
echo "-------------------------------------------------------"

if [ -f $EXECUTABLE ]; then
./$EXECUTABLE -i $INTERFACE -f $OUTFILE
fi