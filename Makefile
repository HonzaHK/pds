#//VUTBR - FIT - PDS project MitM
#//Author: Jan Kubis / xkubis13
CC=g++
CFLAGS=-g -std=c++11 -Wall -Wextra -pedantic
LIB_PCAP=-lpcap
LIB_XML=-I/usr/include/libxml2 -lxml2

SOURCE_PDSLIBS=	pdslib/pds_addr.cpp \
				pdslib/pds_host.cpp \
				pdslib/pds_pkt.cpp


all: clean scanner chooser spoof intercept

#SCANNER --------------------------------------------------
EXE_SCANNER=pds-scanner
SOURCE_SCANNER=pds-scanner.c
scanner: clean
	${CC} ${CFLAGS} ${SOURCE_SCANNER} ${SOURCE_PDSLIBS} -o ${EXE_SCANNER} ${LIB_PCAP} ${LIB_XML}
runscanner: scanner
	sudo ./pds-scanner -i wlp3s0 -f out/detected_devices.xml
	cat out/detected_devices.xml
#----------------------------------------------------------

#CHOOSER --------------------------------------------------
EXE_CHOOSER=pds-chooser
SOURCE_CHOOSER=pds-chooser.c
chooser: clean
	${CC} ${CFLAGS} ${SOURCE_CHOOSER} ${SOURCE_PDSLIBS} -o ${EXE_CHOOSER} ${LIB_XML}
runchooser: chooser
	sudo ./pds-chooser -f in/chooser.xml -o out/chooser.xml
	cat out/chooser.xml
#----------------------------------------------------------

#SPOOF-- --------------------------------------------------
EXE_SPOOF=pds-spoof
SOURCE_SPOOF=pds-spoof.c
spoof: clean
	${CC} ${CFLAGS} ${SOURCE_SPOOF} ${SOURCE_PDSLIBS} -o ${EXE_SPOOF} ${LIB_PCAP} ${LIB_XML}
runspoof: chooser
#----------------------------------------------------------

#INTERCEPT ------------------------------------------------
EXE_INTERCEPT=pds-intercept
SOURCE_INTERCEPT=pds-intercept.c
intercept: clean
	${CC} ${CFLAGS} ${SOURCE_INTERCEPT} ${SOURCE_PDSLIBS} -o ${EXE_INTERCEPT} ${LIB_PCAP} ${LIB_XML}
runintercept: intercept
	sudo ./pds-intercept -i wlp3s0 -f in/inter.xml
#----------------------------------------------------------

clean:
	sudo rm -rf ${EXE_SCANNER} ${EXE_CHOOSER} ${EXE_SPOOF} ${EXE_INTERCEPT}