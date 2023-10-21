all: ipc-benchmark ipc-static ipc-dynamic

CFLAGS=-Wall -g
HEADERS=ipc.h main.h pmc.h

.o: .c ${HEADERS}
	cc ${CFLAGS} -c -Wall -o ${.TARGET} ipc.c -static

main.o: main.c
pmc.o: pmc.c
ipc.o: ipc.c ipc.h

ipc-static: main.o ipc.o pmc.o
	c++ -o ${.TARGET} ${.ALLSRC} -lpmc -lpthread -static -lxo -lutil

ipc-dynamic: main.o ipc.o pmc.o
	c++ -o ${.TARGET} ${.ALLSRC} -lpmc -lpthread -dynamic -lxo -lutil

ipc-benchmark: ipc-dynamic
	cp ${.ALLSRC} ${.TARGET}

clean:
	rm -f ipc-dynamic ipc-static ipc-benchmark main.o ipc.o pmc.o
