SOURCE="pds-chooser.cpp"
EXECUTABLE="pds-chooser"
FLAGS="-std=c++11 -Wall -Wextra -pedantic"
INFILE="detected-devices.xml"
OUTFILE="pair-devices.xml"
LIB_XML="-I/usr/include/libxml2 -lxml2"

if [ -f $EXECUTABLE ]; then
	sudo rm $EXECUTABLE
fi
if [ -f $OUTFILE ]; then
	sudo rm $OUTFILE
fi
# if [ ! -f $INFILE ]; then
# 	exit
# fi


echo "-- COMPILATION ----------------------------------------"
g++ $FLAGS $SOURCE -o $EXECUTABLE $LIB_XML
echo "-------------------------------------------------------"

if [ -f $EXECUTABLE ]; then
sudo ./$EXECUTABLE -f $INFILE -o $OUTFILE
fi