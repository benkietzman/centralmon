#
#	Original Author: Ben Kietzman
#	Original Date: 2008-08-08
#

MAKE_UNAME=`uname -s`
prefix=/usr/local

all: bin/centralmon bin/centralmon_trigger

bin/centralmon: ../common/libcommon.a obj/centralmon.o
	-if [ ! -d bin ]; then mkdir bin; fi;
	if test "$(MAKE_UNAME)" = "Linux"; then g++ -ggdb -o bin/centralmon obj/centralmon.o $(LDFLAGS) -L/data/extras/lib -L../common -lcommon -lb64 -lcrypto -lexpat -lmjson -lnsl -lpthread -lrt -lssl -ltar -lz; elif test "$(MAKE_UNAME)" = "SunOS"; then g++ -ggdb -o bin/centralmon obj/centralmon.o $(LDFLAGS) -L/data/extras/lib -L/usr/local/lib -L/usr/local/ssl/lib -L/opt/csw/lib -L../common -lcommon -lb64 -lcrypto -lexpat -lkstat -lmjson -lnsl -lpthread -lrt -lsocket -lssl -ltar -lz; fi;

bin/centralmond: ../common/libcommon.a obj/centralmond.o
	-if [ ! -d bin ]; then mkdir bin; fi;
	if test "$(MAKE_UNAME)" = "Linux"; then g++ -ggdb -o bin/centralmond obj/centralmond.o $(LDFLAGS) -L/data/extras/lib -L../common -lcommon -lb64 -lcrypto -lexpat -lmjson -lnsl -lpthread -lrt -lssl -ltar -lz; elif test "$(MAKE_UNAME)" = "SunOS"; then g++ -ggdb -o bin/centralmond obj/centralmond.o $(LDFLAGS) -L/data/extras/lib -L/usr/local/lib -L/usr/local/ssl/lib -L/opt/csw/lib -L../common -lcommon -lb64 -lcrypto -lexpat -lmjson -lnsl -lpthread -lrt -lsocket -lssl -ltar -lz; fi;

bin/centralmon_trigger: ../common/libcommon.a obj/centralmon_trigger.o
	-if [ ! -d bin ]; then mkdir bin; fi;
	if test "$(MAKE_UNAME)" = "Linux"; then g++ -ggdb -o bin/centralmon_trigger obj/centralmon_trigger.o $(LDFLAGS) -L/data/extras/lib -L../common -lcommon -lb64 -lcrypto -lexpat -lmjson -lnsl -lpthread -lrt -lssl -ltar -lz; elif test "$(MAKE_UNAME)" = "SunOS"; then g++ -ggdb -o bin/centralmon_trigger obj/centralmon_trigger.o $(LDFLAGS) -L/data/extras/lib -L/usr/local/lib -L/usr/local/ssl/lib -L/opt/csw/lib -L../common -lcommon -lb64 -lcrypto -lexpat -lkstat -lmjson -lnsl -lpthread -lrt -lsocket -lssl -ltar -lz; fi;

../common/libcommon.a:
	cd ../common; ./configure; make;

obj/centralmon.o: centralmon.cpp
	-if [ ! -d obj ]; then mkdir obj; fi;
	if test "$(MAKE_UNAME)" = "Linux"; then g++ -Wall -ggdb -c $< -o $@ -DLINUX $(CPPFLAGS) -I/data/extras/include -I../common; elif test "$(MAKE_UNAME)" = "SunOS"; then g++ -Wall -ggdb -c $< -o $@ -DSOLARIS $(CPPFLAGS) -I/data/extras/include -I/usr/local/ssl/include -I../common; fi;

obj/centralmond.o: centralmond.cpp
	-if [ ! -d obj ]; then mkdir obj; fi;
	if test "$(MAKE_UNAME)" = "Linux"; then g++ -Wall -ggdb -c $< -o $@ -DLINUX $(CPPFLAGS) -I/data/extras/include -I../common; elif test "$(MAKE_UNAME)" = "SunOS"; then g++ -Wall -ggdb -c $< -o $@ -DSOLARIS $(CPPFLAGS) -I/data/extras/include -I/usr/local/ssl/include -I../common; fi;

obj/centralmon_trigger.o: centralmon_trigger.cpp
	-if [ ! -d obj ]; then mkdir obj; fi;
	if test "$(MAKE_UNAME)" = "Linux"; then g++ -Wall -ggdb -c $< -o $@ -DLINUX $(CPPFLAGS) -I/data/extras/include -I../common; elif test "$(MAKE_UNAME)" = "SunOS"; then g++ -Wall -ggdb -c $< -o $@ -DSOLARIS $(CPPFLAGS) -I/data/extras/include -I/usr/local/ssl/include -I../common; fi;

install: bin/centralmon bin/centralmon_trigger
	install --mode=755 bin/centralmon ${prefix}/sbin/
	install --mode=755 bin/centralmon_trigger ${prefix}/sbin/
	if test "$(MAKE_UNAME)" = "Linux"; then if [ ! -f /lib/systemd/system/centralmon.service ]; then install --mode=644 centralmon.service /lib/systemd/system/; fi; if [ ! -f /etc/init/centralmon.conf ]; then install --mode=644 centralmon.conf /etc/init/; fi; elif test "$(MAKE_UNAME)" = "SunOS"; then if [ ! -f ${prefix}/sbin/svc-centralmon.sh ]; then install --mode=777 svc-centralmon.sh ${prefix}/sbin/; fi; fi;

server: bin/centralmond
	install --mode=755 bin/centralmond ${prefix}/sbin/
	if test "$(MAKE_UNAME)" = "Linux"; then if [ ! -f /lib/systemd/system/centralmond.service ]; then install --mode=644 centralmond.service /lib/systemd/system/; fi; if [ ! -f /etc/init/centralmond.conf ]; then install --mode=644 centralmond.conf /etc/init/; fi; elif test "$(MAKE_UNAME)" = "SunOS"; then if [ ! -f ${prefix}/sbin/svc-centralmond.sh ]; then install --mode=777 svc-centralmond.sh ${prefix}/sbin/; fi; fi;

clean:
	-rm -fr obj bin

uninstall:
	-rm -f ${prefix}/sbin/centralmon
	-rm -f ${prefix}/sbin/centralmond
	-rm -f ${prefix}/sbin/centralmon_trigger
	-if test "$(MAKE_UNAME)" = "Linux"; then rm -f /lib/systemd/system/centralmon.service; rm -f /etc/init/centralmon.conf; elif test "$(MAKE_UNAME)" = "SunOS"; then rm -f ${prefix}/sbin/svc-centralmon.sh; fi;
	-if test "$(MAKE_UNAME)" = "Linux"; then rm -f /lib/systemd/system/centralmond.service; rm -f /etc/init/centralmond.conf; elif test "$(MAKE_UNAME)" = "SunOS"; then rm -f ${prefix}/sbin/svc-centralmond.sh; fi;
