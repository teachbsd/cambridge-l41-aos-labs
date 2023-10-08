all: ipc-benchmark ipc-static ipc-dynamic

CFLAGS=-Wall -g

.o: .c
	cc ${CFLAGS} -c -Wall -o ${.TARGET} ipc.c -static

pmc.o: pmc.c pmc.h
ipc.o: pmc.h

ipc-static: ipc.o pmc.o
	c++ -o ${.TARGET} ${.ALLSRC} -lpmc -lpthread -static -lxo -lutil

ipc-dynamic: ipc.o pmc.o
	c++ -o ${.TARGET} ${.ALLSRC} -lpmc -lpthread -dynamic -lxo -lutil

ipc-benchmark: ipc.o pmc.o
	c++ -o ${.TARGET} ${.ALLSRC} -lpmc -lpthread -dynamic -lxo -lutil

clean:
	rm -f ipc-dynamic ipc-static ipc-benchmark pmc.o ipc.o
