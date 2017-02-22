SOURCE="pds-scanner.cpp"
EXECUTABLE="pds-scanner"
FLAGS="-std=c++11 -Wall -Wextra -pedantic"
OUTFILE="scanner_out.xml"
INTERFACE="eth0"

rm $EXECUTABLE $OUTFILE
g++ $FLAGS $SOURCE -o $EXECUTABLE

./$EXECUTABLE -i $INTERFACE -f $OUTFILE