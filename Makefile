#//VUTBR - FIT - PDS project MitM
#//Author: Jan Kubis / xkubis13
CC=g++
CFLAGS=-g -std=c++11 -Wall -Wextra -pedantic
LIB_PCAP=-lpcap
LIB_XML=-I/usr/include/libxml2 -lxml2
ZIP_NAME=xkubis13.zip

SOURCE_PDSLIBS=	pdslib/pds_addr.c pdslib/pds_addr.h \
				pdslib/pds_host.c pdslib/pds_host.h \
				pdslib/pds_pkt.c pdslib/pds_pkt.h


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
MAC_XPERIA=1800.2d30.2d8f
IP4_XPERIA=192.168.0.100
IP6_XPERIA=fe80::1a00:2dff:fe30:2d8f

MAC_LIBRA=001b.9e8a.8696
IP4_LIBRA=192.168.0.101
IP6_LIBRA=fe80::21b:9eff:fe8a:8696

EXE_SPOOF=pds-spoof
SOURCE_SPOOF=pds-spoof.c
spoof: clean
	${CC} ${CFLAGS} ${SOURCE_SPOOF} ${SOURCE_PDSLIBS} -o ${EXE_SPOOF} ${LIB_PCAP} ${LIB_XML}
runspoof4: spoof
	sudo ./pds-spoof -i wlp3s0 -t 3000 -p arp -victim1ip ${IP4_LIBRA} -victim1mac ${MAC_LIBRA} -victim2ip ${IP4_XPERIA} -victim2mac ${MAC_XPERIA}
runspoof6: spoof
	sudo ./pds-spoof -i wlp3s0 -t 3000 -p ndp -victim1ip ${IP6_LIBRA} -victim1mac ${MAC_LIBRA} -victim2ip ${IP6_XPERIA} -victim2mac ${MAC_XPERIA}
#----------------------------------------------------------

#INTERCEPT ------------------------------------------------
EXE_INTERCEPT=pds-intercept
SOURCE_INTERCEPT=pds-intercept.c
intercept: clean
	${CC} ${CFLAGS} ${SOURCE_INTERCEPT} ${SOURCE_PDSLIBS} -o ${EXE_INTERCEPT} ${LIB_PCAP} ${LIB_XML}
runintercept: intercept
	sudo ./pds-intercept -i wlp3s0 -f in/inter.xml
#----------------------------------------------------------

zip: scanner chooser spoof intercept
	zip -r ${ZIP_NAME} \
		${SOURCE_SCANNER} ${SOURCE_CHOOSER} ${SOURCE_SPOOF} ${SOURCE_INTERCEPT} \
		${SOURCE_PDSLIBS} \
		Makefile README.md

clean:
	rm -rf ${EXE_SCANNER} ${EXE_CHOOSER} ${EXE_SPOOF} ${EXE_INTERCEPT} ${ZIP_NAME}