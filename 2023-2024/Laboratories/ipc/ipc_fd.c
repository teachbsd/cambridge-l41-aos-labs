/*-
 * Copyright (c) 2015, 2020-2023 Robert N. M. Watson
 * Copyright (c) 2015 Bjoern A. Zeeb
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <netinet/in.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libxo/xo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "ipc.h"
#include "main.h"

#define	min(x, y)	((x) < (y) ? (x) : (y))

void
sender_fd(struct sender_argument *sap)
{
	ssize_t len;
	long write_sofar;

	write_sofar = 0;
	while (write_sofar < totalsize) {
		const size_t bytes_to_write = min(buffersize, totalsize - write_sofar);
		len = write(sap->sa_write_handle, sap->sa_buffer,
		    min(buffersize, totalsize - write_sofar));
		/*printf("write(%d, %zd, %zd) = %zd\n", sap->sa_write_handle, 0, bytes_to_write, len);*/
		if (len != bytes_to_write) {
			xo_errx(EX_IOERR, "blocking write() returned early: "
			    "%zd != %zd", len, bytes_to_write);
		}
		if (len < 0)
			xo_err(EX_IOERR, "FAIL: write");
		write_sofar += len;
	}
}

void
receiver_fd(intptr_t read_handle, void *buf)
{
	ssize_t len;
	long read_sofar;

	read_sofar = 0;
	/** read() always returns as soon as there is something to read,
	 * i.e. one pipe/socket buffer size. Make sure we use the whole buffer */
	while (read_sofar < totalsize) {
		const size_t offset = read_sofar % buffersize;
		const size_t bytes_to_read = min(totalsize - read_sofar, buffersize - offset);
		len = read(read_handle, buf + offset, bytes_to_read);
		/*printf("read(%d, %zd, %zd) = %zd\n", read_handle, offset, bytes_to_read, len);*/
		/* if (len != bytes_to_read) {
			warn("blocking read returned early: %zd != %zd", len, bytes_to_read);
		} */
		if (len < 0)
			xo_err(EX_IOERR, "FAIL: read");
		read_sofar += len;
	}
}

/*
 * Allocate, configure, as needed connect, and return a pair of IPC object
 * handle via *read_handlep and *write_handlep.
 */
void
ipc_objects_allocate_fd(intptr_t *read_handlep, intptr_t *write_handlep)
{
	struct sockaddr_in sin;
	int fd[2], listenfd, read_handle, write_handle, sockoptval;
	int error, flags, i, integer;

	/*
	 * Allocate a suitable IPC object.
	 */
	switch (ipc_type) {
	case BENCHMARK_IPC_PIPE:
		if (pipe(fd) < 0)
			xo_err(EX_OSERR, "FAIL: pipe");

		/*
		 * On FreeBSD, it doesn't matter which end of the pipe
		 * we use, but on other operating systems, it is
		 * sometimes the case that the first file descriptor
		 * must be used for reading, and the second for
		 * writing.
		 */
		read_handle = fd[0];
		write_handle = fd[1];
		break;

	case BENCHMARK_IPC_LOCAL_SOCKET:
		if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fd) < 0)
			xo_err(EX_OSERR, "FAIL: socketpair");

		/*
		 * With socket pairs, it makes no difference which one
		 * we use for reading or writing.
		 */
		read_handle = fd[0];
			write_handle = fd[1];
		break;

	case BENCHMARK_IPC_TCP_SOCKET:
		/*
		 * Flush the TCP host cache before starting the benchmark,
		 * to prevent retained RTT/bandwidth estimates from
		 * influencing performance results.
		 */
		integer = 1;
		if (sysctlbyname("net.inet.tcp.hostcache.purgenow", NULL,
		    NULL, &integer, sizeof(integer)) < 0)
			xo_err(EX_OSERR,
			    "sysctlbyname: net.inet.tcp.hostcache.purgenow");

		/*
		 * Listen socket and a corresponding socket address used for
		 * both binding and connecting.
		 */
		listenfd = socket(PF_INET, SOCK_STREAM, 0);
		if (listenfd < 0)
			xo_err(EX_OSERR, "FAIL: socket (listen)");
		i = 1;
		if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &i,
		    sizeof(i)) < 0)
			xo_err(EX_OSERR, "FAIL: setsockopt SO_REUSEADDR");
		bzero(&sin, sizeof(sin));
		sin.sin_len = sizeof(sin);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sin.sin_port = htons(tcp_port);
		if (bind(listenfd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
			xo_err(EX_OSERR, "FAIL: bind");
		if (listen(listenfd, -1) < 0)
			xo_err(EX_OSERR, "FAIL: listen");

		/*
		 * Create the 'read' endpoint and connect it to the listen
		 * socket in a non-blocking manner (as we need to accept()
		 * it before the connection can complete, and don't want to
		 * deadlock).
		 *
		 * Note that it *does* matter which we use for reading vs.
		 * writing -- we intentionally wait until the full three-way
		 * handshake is done before transmitting data, and only the
		 * accepted socket has this property (i.e., waiting for the
		 * ACK in the SYN-SYN/ACK-ACK exchange).
		 */
		read_handle = socket(PF_INET, SOCK_STREAM, 0);
		if (read_handle < 0)
			xo_err(EX_OSERR, "FAIL: socket (read)");
		flags = fcntl(read_handle, F_GETFL, 0);
		if (flags < 0)
			xo_err(EX_OSERR, "FAIL: fcntl(read_handle, F_GETFL, 0)");
		if (fcntl(read_handle, F_SETFL, flags | O_NONBLOCK) < 0)
			xo_err(EX_OSERR, "FAIL: fcntl(read_handle, F_SETFL, "
			    "flags | O_NONBLOCK)");
		error = connect(read_handle, (struct sockaddr *)&sin,
		    sizeof(sin));
		if (error < 0 && errno != EINPROGRESS)
			xo_err(EX_OSERR, "FAIL: connect");

		/*
		 * On the listen socket, now accept the 'write' endpoint --
		 * which should block until the full three-way handshake is
		 * complete.
		 */
		write_handle = accept(listenfd, NULL, NULL);
		if (write_handle < 0)
			xo_err(EX_OSERR, "accept");

		/*
		 * Restore blocking status to the 'read' endpoint, and close
		 * the now-unnecessary listen socket.  Any further use of
		 * the 'read' endpoint will block until the socket is ready,
		 * although in practice that is unlikely.
		 */
		if (fcntl(read_handle, F_SETFL, flags) < 0)
			xo_err(EX_OSERR, "FAIL: fcntl(read_handle, F_SETFL, "
			    "flags");
		close(listenfd);
		break;

	default:
		assert(0);
	}


	if (ipc_type == BENCHMARK_IPC_LOCAL_SOCKET ||
	    ipc_type == BENCHMARK_IPC_TCP_SOCKET) {
		if (sflag) {
			/*
			 * Default socket-buffer sizes may be too low (e.g.,
			 * 8K) to allow atomic sends/receives of our requested
			 * buffer length.  Extend both socket buffers to fit
			 * better.
			 */
			sockoptval = buffersize;
			if (setsockopt(write_handle, SOL_SOCKET, SO_SNDBUF,
			    &sockoptval, sizeof(sockoptval)) < 0)
				xo_err(EX_OSERR, "FAIL: setsockopt "
				    "SO_SNDBUF");
			if (setsockopt(read_handle, SOL_SOCKET, SO_RCVBUF,
			    &sockoptval, sizeof(sockoptval)) < 0)
				xo_err(EX_OSERR, "FAIL: setsockopt "
				    "SO_RCVBUF");
		}
	}
	*read_handlep = read_handle;
	*write_handlep = write_handle;
}

void
ipc_objects_free_fd(intptr_t read_handle, intptr_t write_handle)
{

	close(read_handle);
	close(write_handle);
}
