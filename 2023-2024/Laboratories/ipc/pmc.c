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
#include <sys/cpuset.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <net/if.h>

#include <netinet/in.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pmc.h>
#include <libxo/xo.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include "main.h"
#include "pmc.h"

/* Always collect this data; allow other counters to be configured. */
#define	COUNTERSET_HEADER						\
	"INST_RETIRED",		/* Instructions retired */		\
	"CPU_CYCLES"		/* Cycle counter */

/*
 * In principle ARMv8-A supports non-speculative LD_RETIRED, ST_RETIRED, and
 * BR_RETURN_RETIRED.  However, the A72 doesn't, so we have to use counters
 * for speculatively executed operations.  Possibly we might prefer to use the
 * MEM_ACCESS_LD and MEM_ACCESS_ST counters instead.  But, as a result of all
 * of this, 'arch' isn't really representative.
 */
static const char *counterset_arch[COUNTERSET_MAX_EVENTS] = {
	COUNTERSET_HEADER,
	"LD_SPEC",		/* Speculated loads (any width) */
	"ST_SPEC",		/* Speculated stores (any width) */
	"EXC_RETURN",		/* Architectural exception returns */
	"BR_RETURN_SPEC",	/* Speculated function returns */
};

#define	COUNTERSET_HEADER_INSTR_EXECUTED	0	/* Array index */
#define	COUNTERSET_HEADER_CLOCK_CYCLES		1	/* Array index */

/*
 * NB: Keep INDEX constants in sync, as they are used to calculate derived
 * values such as cache miss rates.
 */
static const char *counterset_dcache[COUNTERSET_MAX_EVENTS] = {
	COUNTERSET_HEADER,
#define	COUNTERSET_DCACHE_INDEX_L1D_CACHE		2
	"L1D_CACHE",		/* Level-1 data-cache hits */
#define	COUNTERSET_DCACHE_INDEX_L1D_CACHE_REFILL	3
	"L1D_CACHE_REFILL",	/* Level-1 data-cache misses */
#define	COUNTERSET_DCACHE_INDEX_L2D_CACHE		4
	"L2D_CACHE",		/* Level-2 cache hits */
#define	COUNTERSET_DCACHE_INDEX_L2D_CACHE_REFILL	5
	"L2D_CACHE_REFILL",	/* Level-2 cache misses */
};

static const char *counterset_instr[COUNTERSET_MAX_EVENTS] = {
	COUNTERSET_HEADER,
#define	COUNTERSET_INSTR_INDEX_L1I_CACHE		2
	"L1I_CACHE",		/* Level-1 instruction-cache hits */
#define	COUNTERSET_INSTR_INDEX_L1I_CACHE_REFILL		3
	"L1I_CACHE_REFILL",	/* Level-1 instruction-cache misses */
#define	COUNTERSET_INSTR_INDEX_BR_MIS_PRED		4
	"BR_MIS_PRED",		/* Speculative branch mispredicted */
#define	COUNTERSET_INSTR_INDEX_BR_PRED			5
	"BR_PRED",		/* Specualtive branch predicted */
};

static const char *counterset_tlbmem[COUNTERSET_MAX_EVENTS] = {
	COUNTERSET_HEADER,
	"L1D_TLB_REFILL",	/* Data-TLB refills */
	"L1I_TLB_REFILL",	/* Instruction-TLB refills */
	"MEM_ACCESS",		/* Memory reads/writes issued by instructions */
	"BUS_ACCESS",		/* Memory accesses over the bus */
};

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
unsigned int benchmark_pmc = BENCHMARK_PMC_NONE;

pmc_id_t pmcid[COUNTERSET_MAX_EVENTS];
uint64_t pmc_values[COUNTERSET_MAX_EVENTS];

const char **counterset;		/* The actual counter set in use. */

void
pmc_setup_run(void)
{
	int i;

	switch (benchmark_pmc) {
	case BENCHMARK_PMC_NONE:
		return;

	case BENCHMARK_PMC_ARCH:
		counterset = counterset_arch;
		break;

	case BENCHMARK_PMC_DCACHE:
		counterset = counterset_dcache;
		break;

	case BENCHMARK_PMC_INSTR:
		counterset = counterset_instr;
		break;

	case BENCHMARK_PMC_TLBMEM:
		counterset = counterset_tlbmem;
		break;

	default:
		assert(0);
	}

	/*
	 * Use process-mode counting that descends to children processes --
	 * i.e., to properly account for child behaviour in 2proc.
	 */
	bzero(pmc_values, sizeof(pmc_values));
	for (i = 0; i < COUNTERSET_MAX_EVENTS; i++) {
		if (counterset[i] == NULL)
			continue;
		if (pmc_allocate(counterset[i], PMC_MODE_TC,
		    PMC_F_DESCENDANTS, PMC_CPU_ANY, &pmcid[i], 64*1024) < 0)
			xo_err(EX_OSERR, "FAIL: pmc_allocate %s",
			    counterset[i]);
		if (pmc_attach(pmcid[i], 0) != 0)
			xo_err(EX_OSERR, "FAIL: pmc_attach %s",
			    counterset[i]);
		if (pmc_write(pmcid[i], 0) < 0)
			xo_err(EX_OSERR, "FAIL: pmc_write  %s",
			    counterset[i]);
	}
}

void
pmc_teardown_run(void)
{
	int i;

	for (i = 0; i < COUNTERSET_MAX_EVENTS; i++) {
		if (counterset[i] == NULL)
			continue;
		if (pmc_detach(pmcid[i], 0) != 0)
			xo_err(EX_OSERR, "FAIL: pmc_detach %s",
			    counterset[i]);
		if (pmc_release(pmcid[i]) < 0)
			xo_err(EX_OSERR, "FAIL: pmc_release %s",
			    counterset[i]);
	}
}

int
benchmark_pmc_from_string(const char *string)
{

	if (strcmp(BENCHMARK_PMC_NONE_STRING, string) == -0)
		return (BENCHMARK_PMC_NONE);
	else if (strcmp(BENCHMARK_PMC_ARCH_STRING, string) == 0)
		return (BENCHMARK_PMC_ARCH);
	else if (strcmp(BENCHMARK_PMC_DCACHE_STRING, string) == 0)
		return (BENCHMARK_PMC_DCACHE);
	else if (strcmp(BENCHMARK_PMC_INSTR_STRING, string) == 0)
		return (BENCHMARK_PMC_INSTR);
	else if (strcmp(BENCHMARK_PMC_TLBMEM_STRING, string) == 0)
		return (BENCHMARK_PMC_TLBMEM);
	else
		return (BENCHMARK_PMC_INVALID);
}

const char *
benchmark_pmc_to_string(int type)
{

	switch (type) {
	case BENCHMARK_PMC_NONE:
		return (BENCHMARK_PMC_NONE_STRING);

	case BENCHMARK_PMC_ARCH:
		return (BENCHMARK_PMC_ARCH_STRING);

	case BENCHMARK_PMC_DCACHE:
		return (BENCHMARK_PMC_DCACHE_STRING);

	case BENCHMARK_PMC_INSTR:
		return (BENCHMARK_PMC_INSTR_STRING);

	case BENCHMARK_PMC_TLBMEM:
		return (BENCHMARK_PMC_TLBMEM_STRING);

	default:
		return (BENCHMARK_PMC_INVALID_STRING);
	}
}

void
pmc_print(void)
{
	float f;
	int i;

	if (benchmark_pmc == BENCHMARK_PMC_NONE)
		return;

	/* Print baseline measured counters. */
	for (i = 0; i < COUNTERSET_MAX_EVENTS; i++) {
		if (counterset[i] == NULL)
			continue;
		if (jflag)
			xo_emit_field("V", counterset[i],
			  NULL, "%ju", pmc_values[i]);
		else
			xo_emit_field("V", counterset[i],
			    "  %s: %ju\n", NULL, counterset[i],
			    pmc_values[i]);
	}

	/*
	 * Print out a few derived metrics that are easier to calculate here
	 * than later.
	 */
	xo_emit("  CYCLES_PER_INSTRUCTION: {:CYCLES_PER_INSTRUCTION/%F}\n",
	    (float)pmc_values[COUNTERSET_HEADER_CLOCK_CYCLES] /
	    (float)pmc_values[COUNTERSET_HEADER_INSTR_EXECUTED]);
	if (benchmark_pmc == BENCHMARK_PMC_DCACHE) {
		f = pmc_values[COUNTERSET_DCACHE_INDEX_L1D_CACHE] -
		   pmc_values[COUNTERSET_DCACHE_INDEX_L1D_CACHE_REFILL];
		f /= pmc_values[COUNTERSET_DCACHE_INDEX_L1D_CACHE];
		xo_emit("  L1D_CACHE_HIT_RATE: "
		   "{:L1D_CACHE_HIT_RATE/%F}\n", f);

		f = pmc_values[COUNTERSET_DCACHE_INDEX_L2D_CACHE] -
		   pmc_values[COUNTERSET_DCACHE_INDEX_L2D_CACHE_REFILL];
		f /= pmc_values[COUNTERSET_DCACHE_INDEX_L2D_CACHE];
		xo_emit("  L2D_CACHE_HIT_RATE: "
		   "{:L2D_CACHE_HIT_RATE/%F}\n", f);
	}
	if (benchmark_pmc == BENCHMARK_PMC_INSTR) {
		f = pmc_values[COUNTERSET_INSTR_INDEX_L1I_CACHE] -
		    pmc_values[COUNTERSET_INSTR_INDEX_L1I_CACHE_REFILL];
		f /= pmc_values[COUNTERSET_INSTR_INDEX_L1I_CACHE];
		xo_emit("  L1I_CACHE_HIT_RATE: "
		    "{:L1I_CACHE_HIT_RATE/%F}\n", f);

		f = pmc_values[COUNTERSET_INSTR_INDEX_BR_PRED];
		f /= pmc_values[COUNTERSET_INSTR_INDEX_BR_MIS_PRED] +
		    pmc_values[COUNTERSET_INSTR_INDEX_BR_PRED];
		xo_emit("  BR_PRED_RATE: "
		    "{:BR_PRED_RATE/%F}\n", f);
	}
}
