all: io-static io-dynamic

io-static: io.c
	cc -Wall -o ${.TARGET} -DPROGNAME=\"${.TARGET}\" io.c -static -lxo \
	    -lutil
io-dynamic: io.c
	cc -Wall -o ${.TARGET} -DPROGNAME=\"${.TARGET}\" io.c -dynamic -lxo \
	    -lutil

clean:
	rm -f io-dynamic io-static
