all: ipc-static ipc-dynamic

CFLAGS=-DWITH_PMC -Wall

ipc-static: ipc-static.o
	c++ -o ${.TARGET} ${.ALLSRC} -lpmc -lpthread -static

ipc-static.o: ipc.c
	cc ${CFLAGS} -c -o ${.TARGET} -DPROGNAME=\"${.TARGET}\" ipc.c -static

ipc-dynamic: ipc-dynamic.o
	c++ -o ${.TARGET} ${.ALLSRC} -lpmc -lpthread -dynamic

ipc-dynamic.o: ipc.c
	cc ${CFLAGS} -c -o ${.TARGET} -DPROGNAME=\"${.TARGET}\" ipc.c -dynamic

clean:
	rm -f ipc-dynamic.o ipc-dynamic ipc-static.o ipc-static
