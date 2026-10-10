/*
 * trace.h - tiny boot-trace recorder that writes trace-cmd v6 or Perfetto files
 *
 * Typical use:
 *
 *     trace_add("barebox started");
 *     ... do work ...
 *     trace_add("kernel loaded");
 *     trace_write("trace.dat");            // open with `trace-cmd report` or KernelShark
 *     trace_write_perfetto("trace.pftrace"); // open with ui.perfetto.dev
 *     trace_free();
 *
 * All functions return 0 on success and -1 with errno set on failure.
 * The recorder keeps one global list, so it is not thread-safe.
 */
#ifndef TRACE_H
#define TRACE_H

#include <stddef.h>
#include <stdint.h>

/* Append a task string, timestamped now (CLOCK_MONOTONIC). 0 or -1/errno. */
int trace_add(const char *task);

/*
 * Append a task string with an explicit timestamp in nanoseconds.
 * Mainly for tests and for callers that already have their own clock.
 */
int trace_add_at(uint64_t ts_ns, const char *task);

/*
 * Write all recorded entries to path as a trace-cmd v6 trace.dat.
 * An empty list produces a valid file with no events.
 * errno: EINVAL (NULL path), ENOMEM, EMSGSIZE (a message over ~4 KB),
 * or whatever fopen/fwrite reported.
 */
int trace_write(const char *path);

/*
 * Write all recorded entries to path as a Perfetto trace (protobuf
 * TrackEvents), openable in the Perfetto UI (ui.perfetto.dev) and with
 * trace_processor.  Each message becomes an instant event on the track
 * "barebox tasks" and a slice on "barebox stages" that lasts until the
 * next message (the final slice has duration 0).  An empty list produces
 * a valid trace with no events.  errno: EINVAL (NULL path), ENOMEM, or
 * whatever fopen/fwrite reported.
 */
int trace_write_perfetto(const char *path);

/* Release all entries. The list is empty afterwards. */
void trace_free(void);

/* Number of entries currently recorded. */
size_t trace_count(void);

#endif
