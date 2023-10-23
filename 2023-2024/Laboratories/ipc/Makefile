all: ipc-benchmark ipc-static ipc-dynamic

CFLAGS=-Wall -g
HEADERS=ipc.h main.h pmc.h
OBJECTS=main.o ipc.o ipc_fd.o ipc_shmem.o pmc.o

.o: .c ${HEADERS}
	cc ${CFLAGS} -c -Wall -o ${.TARGET} ipc.c -static

ipc-static: ${OBJECTS}
	c++ -o ${.TARGET} ${.ALLSRC} -lpmc -lpthread -static -lxo -lutil

ipc-dynamic: ${OBJECTS}
	c++ -o ${.TARGET} ${.ALLSRC} -lpmc -lpthread -dynamic -lxo -lutil

ipc-benchmark: ipc-dynamic
	cp ${.ALLSRC} ${.TARGET}

clean:
	rm -f ipc-dynamic ipc-static ipc-benchmark main.o ipc.o pmc.o
