SOURCE="pds-chooser.cpp"
EXECUTABLE="pds-chooser"
FLAGS="-std=c++11 -Wall -Wextra -pedantic"
INFILE="chooser_in.xml"
OUTFILE="chooser_out.xml"
LIB_XML="-I/usr/include/libxml2 -lxml2"

if [ -f $EXECUTABLE ]; then
	sudo rm $EXECUTABLE
fi
if [ -f $OUTFILE ]; then
	sudo rm $OUTFILE
fi


echo "-- COMPILATION ----------------------------------------"
g++ $FLAGS $SOURCE -o $EXECUTABLE $LIB_XML
echo "-------------------------------------------------------"

if [ -f $EXECUTABLE ]; then
sudo ./$EXECUTABLE -f $INFILE -o $OUTFILE
fi