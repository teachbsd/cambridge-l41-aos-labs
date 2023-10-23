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

#ifndef MAIN_H
#define	MAIN_H

extern unsigned int Bflag;	/* bare */
extern unsigned int gflag;	/* getrusage */
extern unsigned int jflag;	/* JSON */
extern unsigned int qflag;	/* quiet */
extern unsigned int sflag;	/* set socket-buffer sizes */

#define	BENCHMARK_MODE_INVALID		-1
#define	BENCHMARK_MODE_2THREAD		2
#define	BENCHMARK_MODE_2PROC		3
#define	BENCHMARK_MODE_DESCRIBE		4

#define	BENCHMARK_IPC_INVALID		-1
#define	BENCHMARK_IPC_PIPE		1
#define	BENCHMARK_IPC_LOCAL_SOCKET	2
#define	BENCHMARK_IPC_TCP_SOCKET	3
#define	BENCHMARK_IPC_SHMEM		4

extern unsigned int benchmark_mode;
extern unsigned int ipc_type;
extern unsigned short tcp_port;
extern long msgcount;
extern long buffersize;
extern long iterations;
extern long totalsize;

#endif /* MAIN_H */
