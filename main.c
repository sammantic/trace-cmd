/*
 * main.c - demo: pretend to be a bootloader and record its stages
 *
 * Records a fixed list of barebox-style boot stages, sleeping a few
 * milliseconds between them so the resulting timeline looks realistic,
 * then writes everything to trace.dat (or the path given with -o), in the
 * format given with -f (trace-cmd "dat" or "perfetto").
 *
 * Try:  make && ./tracegen && trace-cmd report trace.dat
 *       ./tracegen -f perfetto -o trace.pftrace   # open in ui.perfetto.dev
 */
#define _POSIX_C_SOURCE 200809L	/* for nanosleep() and getopt() */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "trace.h"

/* One dummy boot stage. */
struct stage {
	const char *task;	/* message that ends up in the trace */
	unsigned delay_ms;	/* sleep before recording this stage */
};

/*
 * The fake boot sequence.  Delays are made up but in a plausible range.
 * One of them is deliberately longer than 134 ms so the writer has to use
 * a time-extend record, which keeps that code path exercised every run.
 */
static const struct stage stages[] = {
	{ "barebox started",     0 },
	{ "board init done",     12 },
	{ "console ready",       3 },
	{ "mounting boot fs",    40 },
	{ "loading kernel",      8 },
	{ "kernel loaded",       150 },	/* > 134 ms: exercises time-extend */
	{ "loading device tree", 6 },
	{ "booting kernel",      25 },
};

static void sleep_ms(unsigned ms)
{
	struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };

	nanosleep(&ts, NULL);
}

int main(int argc, char **argv)
{
	const char *path = NULL;
	const char *format = "dat";
	int use_perfetto = 0;
	size_t i;
	int opt;

	/* Options: -f <dat|perfetto>, -o <file>, -h prints usage. */
	while ((opt = getopt(argc, argv, "f:o:h")) != -1) {
		switch (opt) {
		case 'f':
			format = optarg;
			break;
		case 'o':
			path = optarg;
			break;
		case 'h':
			printf("usage: %s [-f dat|perfetto] [-o trace.dat]\n", argv[0]);
			return 0;
		default:
			fprintf(stderr, "usage: %s [-f dat|perfetto] [-o trace.dat]\n", argv[0]);
			return 1;
		}
	}
	if (!strcmp(format, "dat")) {
		;
	} else if (!strcmp(format, "perfetto")) {
		use_perfetto = 1;
	} else {
		fprintf(stderr, "%s: unknown format '%s' (use dat or perfetto)\n",
			argv[0], format);
		return 1;
	}
	if (!path)
		path = use_perfetto ? "trace.pftrace" : "trace.dat";

	/* "Boot": wait, then record each stage in order. */
	for (i = 0; i < sizeof stages / sizeof stages[0]; i++) {
		sleep_ms(stages[i].delay_ms);
		if (trace_add(stages[i].task) < 0) {
			fprintf(stderr, "tracegen: trace_add: %s\n", strerror(errno));
			trace_free();
			return 1;
		}
	}

	/* Everything is in memory now; write it out in one go. */
	if (use_perfetto ? trace_write_perfetto(path) < 0 : trace_write(path) < 0) {
		fprintf(stderr, "tracegen: %s: %s\n", path, strerror(errno));
		trace_free();
		return 1;
	}
	trace_free();
	printf("wrote %zu events to %s\n", i, path);
	return 0;
}
