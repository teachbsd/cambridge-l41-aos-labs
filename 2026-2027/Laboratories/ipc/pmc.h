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

#ifndef PMC_H
#define	PMC_H

#define	BENCHMARK_PMC_NONE_STRING	"none"
#define	BENCHMARK_PMC_INVALID_STRING	"invalid"
#define	BENCHMARK_PMC_ARCH_STRING	"arch"
#define	BENCHMARK_PMC_DCACHE_STRING	"dcache"
#define	BENCHMARK_PMC_INSTR_STRING	"instr"
#define	BENCHMARK_PMC_TLBMEM_STRING	"tlbmem"

#define	BENCHMARK_PMC_INVALID		-1
#define	BENCHMARK_PMC_NONE		0
#define	BENCHMARK_PMC_ARCH		1
#define	BENCHMARK_PMC_DCACHE		2
#define	BENCHMARK_PMC_INSTR		3
#define	BENCHMARK_PMC_TLBMEM		4

#define	BENCHMARK_PMC_DEFAULT	BENCHMARK_PMC_NONE
extern unsigned int benchmark_pmc;

#define	COUNTERSET_MAX_EVENTS	6	/* Maximum hardware registers */

/* Used by inline functions in this header. */
extern pmc_id_t pmcid[COUNTERSET_MAX_EVENTS];
extern uint64_t pmc_values[COUNTERSET_MAX_EVENTS];
extern const char **counterset;

void	pmc_setup_run(void);
void	pmc_teardown_run(void);
void	pmc_print(void);
int	benchmark_pmc_from_string(const char *string);
const char *benchmark_pmc_to_string(int type);

static __inline void
pmc_begin(void)
{
	int i;

	for (i = 0; i < COUNTERSET_MAX_EVENTS; i++) {
		if (counterset[i] == NULL)
			continue;
		if (pmc_start(pmcid[i]) < 0)
			xo_err(EX_OSERR, "FAIL: pmc_start %s", counterset[i]);
	}
}

static __inline void
pmc_end(void)
{
	int i;

	for (i = 0; i < COUNTERSET_MAX_EVENTS; i++) {
		if (counterset[i] == NULL)
			continue;
		if (pmc_read(pmcid[i], &pmc_values[i]) < 0)
			xo_err(EX_OSERR, "FAIL: pmc_read %s", counterset[i]);
	}
	for (i = 0; i < COUNTERSET_MAX_EVENTS; i++) {
		if (counterset[i] == NULL)
			continue;
		if (pmc_stop(pmcid[i]) < 0)
			xo_err(EX_OSERR, "FAIL: pmc_stop %s", counterset[i]);
	}
}

#endif /* PMC_H */
