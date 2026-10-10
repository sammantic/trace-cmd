/*
 * trace.c - record boot-stage messages and write them as a trace.dat file
 *
 * This file has three parts:
 *
 *   1. A recorder.  trace_add("kernel loaded") takes a timestamp and appends
 *      the message to an in-memory linked list.  Nothing is written to disk
 *      yet, so recording is cheap and can happen while the "boot" is running.
 *
 *   2. A trace-cmd writer.  trace_write("trace.dat") walks that list once
 *      and produces a file in the trace-cmd "version 6" format.  That is the
 *      format the Linux tool `trace-cmd record` produces and
 *      `trace-cmd report` and KernelShark read.  We generate it by hand,
 *      without libtraceevent, so the code below documents the format as it
 *      goes.
 *
 *   3. A Perfetto writer.  trace_write_perfetto("trace.pftrace") walks the
 *      same list and produces a Perfetto trace (protobuf TrackEvents), the
 *      format ui.perfetto.dev and trace_processor read.  It is also encoded
 *      by hand; see the comment above part 3 for the packet layout.
 *
 * Big picture of a trace.dat v6 file
 * ----------------------------------
 *
 *   +------------------------------------------------------------------+
 *   | magic + version + endianness + page size                         |
 *   | "header_page"  : describes the layout of one ring-buffer page    |
 *   | "header_event" : describes the 32-bit header in front of events  |
 *   | ftrace event formats        (we have none)                       |
 *   | event systems  -> "barebox" -> event "task" format text          |
 *   | kallsyms       (empty)                                           |
 *   | printk formats (empty)                                           |
 *   | saved cmdlines : "1 barebox"  (pid 1 is shown as "barebox")      |
 *   | number of CPUs : 1                                               |
 *   | "options  "    : option list, we only write the terminator       |
 *   | "flyrecord"    : for each CPU, where its data lives (offset,size)|
 *   | zero padding up to the next 4096-byte boundary                   |
 *   +------------------------------------------------------------------+
 *   | CPU 0 data: one or more 4096-byte ring-buffer pages              |
 *   +------------------------------------------------------------------+
 *
 * Everything in the header part is a text description of the binary data
 * that follows, which is why the reader can decode our custom "task" event
 * without knowing about it in advance.
 *
 * Assumptions: 64-bit little-endian Linux host (numbers are written in
 * host byte order, and the file says "little endian, long is 8 bytes").
 */

#define _POSIX_C_SOURCE 200809L	/* for strdup() and clock_gettime() */
#include "trace.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ================================================================== */
/* Part 1: the recorder (a singly linked list of entries)             */
/* ================================================================== */

/* One recorded message. */
struct entry {
	uint64_t ts_ns;		/* when it happened, nanoseconds, monotonic clock */
	char *task;		/* our own heap copy of the message */
	struct entry *next;	/* next entry in recording order, or NULL */
};

/*
 * The list itself.  `head` is the oldest entry, `tail` the newest so that
 * appending is O(1).  `count` is only kept for trace_count().
 */
static struct entry *head;
static struct entry *tail;
static size_t count;

/*
 * Append a message with an explicit timestamp.
 *
 * This is the real implementation; trace_add() just supplies "now".  Tests
 * use this directly so they can produce exact, reproducible files.
 */
int trace_add_at(uint64_t ts_ns, const char *task)
{
	struct entry *e;

	if (!task) {
		errno = EINVAL;
		return -1;
	}
	e = malloc(sizeof(*e));
	if (!e) {
		errno = ENOMEM;
		return -1;
	}
	/* Copy the string: the caller's buffer may not outlive the list. */
	e->task = strdup(task);
	if (!e->task) {
		free(e);
		errno = ENOMEM;
		return -1;
	}
	e->ts_ns = ts_ns;
	e->next = NULL;

	/* Link it at the end.  An empty list has both head and tail NULL. */
	if (tail)
		tail->next = e;
	else
		head = e;
	tail = e;
	count++;
	return 0;
}

/*
 * Append a message timestamped with the current time.
 *
 * CLOCK_MONOTONIC never jumps backwards (unlike the wall clock), which is
 * what a trace viewer expects.  Its zero point is arbitrary (usually system
 * boot), so the absolute values only matter relative to each other.
 */
int trace_add(const char *task)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		return -1;
	return trace_add_at((uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec,
			    task);
}

/* Free every entry and return to the empty state. Safe to call twice. */
void trace_free(void)
{
	struct entry *e = head;

	while (e) {
		struct entry *next = e->next;	/* read before freeing e */
		free(e->task);
		free(e);
		e = next;
	}
	head = tail = NULL;
	count = 0;
}

size_t trace_count(void)
{
	return count;
}

/* ================================================================== */
/* Part 2: the trace.dat v6 writer                                    */
/* ================================================================== */

#define PAGE_SIZE	4096u	/* size of one ring-buffer page in the file */
#define PAGE_HDR	16u	/* page header: u64 timestamp + u64 commit */
#define TASK_ID		1000u	/* our event's numeric ID (must match task_format) */
#define TASK_PID	1u	/* fake process ID shown for every event */

/*
 * The three text blocks below are copied almost verbatim from what a Linux
 * kernel exposes under /sys/kernel/tracing/.  trace-cmd stores them in the
 * file so that the reader knows how to decode the binary pages.
 */

/*
 * Layout of one ring-buffer page (from events/header_page):
 *   bytes  0..7  : u64 timestamp of the first event on the page
 *   bytes  8..15 : "commit" = how many bytes of event data the page holds
 *   bytes 16..   : the events themselves (4080 bytes available)
 */
static const char header_page[] =
"\tfield: u64 timestamp;\toffset:0;\tsize:8;\tsigned:0;\n"
"\tfield: local_t commit;\toffset:8;\tsize:8;\tsigned:1;\n"
"\tfield: int overwrite;\toffset:8;\tsize:1;\tsigned:1;\n"
"\tfield: char data;\toffset:16;\tsize:4080;\tsigned:0;\n";

/*
 * Layout of the 32-bit word in front of every event (events/header_event):
 *   bits  0..4  : type_len   - record length in 4-byte words (1..28), or a
 *                              special value: 0 = length follows in the next
 *                              word, 30 = time-extend record, 29/31 = other
 *   bits  5..31 : time_delta - nanoseconds since the previous event
 */
static const char header_event[] =
"# compressed entry header\n"
"\ttype_len    :    5 bits\n"
"\ttime_delta  :   27 bits\n"
"\tarray       :   32 bits\n"
"\n"
"\tpadding     : type == 29\n"
"\ttime_extend : type == 30\n"
"\ttime_stamp : type == 31\n"
"\tdata max type_len  == 28\n";

/*
 * Our one custom event, in the same syntax as
 * /sys/kernel/tracing/events/<system>/<event>/format.
 *
 * Every event starts with the four "common" fields (8 bytes).  After them we
 * have a single dynamic string field.  A `__data_loc` field is a 4-byte
 * value: low 16 bits = offset of the string from the start of the record,
 * high 16 bits = its length including the NUL.  The string bytes follow the
 * fixed fields.  The print format tells the reader to show just the string.
 *
 * Record layout in the file (offsets from the start of the record):
 *   0  u16 common_type          = 1000
 *   2  u8  common_flags         = 0
 *   3  u8  common_preempt_count = 0
 *   4  s32 common_pid           = 1
 *   8  u32 msg (__data_loc)     = 12 | (len << 16)
 *  12  char[len] the message, NUL-terminated, padded to a multiple of 4
 */
static const char task_format[] =
"name: task\n"
"ID: 1000\n"
"format:\n"
"\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n"
"\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n"
"\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n"
"\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n"
"\n"
"\tfield:__data_loc char[] msg;\toffset:8;\tsize:4;\tsigned:1;\n"
"\n"
"print fmt: \"%s\", __get_str(msg)\n";

/* "pid comm" pairs; lets the reader print "barebox-1" instead of "<...>-1". */
static const char saved_cmdlines[] = "1 barebox\n";

/* The ring-buffer pages for CPU 0, built in memory before writing. */
struct pages {
	uint8_t *buf;		/* npages * PAGE_SIZE bytes, or NULL */
	size_t npages;
};

#define DELTA_BITS	27u			/* width of time_delta in the event header */
#define DELTA_MAX	((1ull << DELTA_BITS) - 1)	/* ~134 ms in nanoseconds */
#define TYPE_TIME_EXTEND 30u			/* type_len value of a time-extend record */
#define MAX_SMALL_RECORD 112u			/* 28 words: largest length type_len can express */
#define PAGE_DATA	(PAGE_SIZE - PAGE_HDR)	/* bytes available for events per page */

/* Store little-endian integers without alignment worries. */
static void put16(uint8_t *d, uint16_t v) { memcpy(d, &v, sizeof v); }
static void put32(uint8_t *d, uint32_t v) { memcpy(d, &v, sizeof v); }
static void put64(uint8_t *d, uint64_t v) { memcpy(d, &v, sizeof v); }

/* Add one more zero-filled page to the buffer. */
static int pages_grow(struct pages *p)
{
	uint8_t *nb = realloc(p->buf, (p->npages + 1) * PAGE_SIZE);

	if (!nb) {
		errno = ENOMEM;
		return -1;
	}
	memset(nb + p->npages * PAGE_SIZE, 0, PAGE_SIZE);
	p->buf = nb;
	p->npages++;
	return 0;
}

/*
 * Serialise the entry list into ring-buffer pages.
 *
 * Timestamps are stored as small deltas, not absolute values: each page
 * header carries the absolute time of its first event, and every event
 * header carries "nanoseconds since the previous event" in 27 bits.  When a
 * gap is larger than 27 bits can hold (about 134 ms) we first emit a
 * "time-extend" record that carries the whole gap in 27 + 32 bits; the data
 * event that follows then has a delta of 0.  This is exactly what the kernel
 * does, so trace-cmd decodes it natively.
 *
 * The reader keeps a running clock: page timestamp, then + each delta.  Our
 * `last_ts` mirrors that clock so the deltas we write stay consistent.
 *
 * Returns 0, or -1 with errno = ENOMEM or EMSGSIZE (a message too big to
 * ever fit on a page).
 */
static int build_pages(struct pages *p)
{
	const struct entry *e;
	uint8_t *page = NULL;	/* page currently being filled */
	size_t used = 0;	/* data bytes used on that page */
	uint64_t last_ts = 0;	/* the reader's running clock */

	p->buf = NULL;
	p->npages = 0;

	for (e = head; e; e = e->next) {
		size_t len = strlen(e->task) + 1;		/* string incl NUL */
		size_t rec = (12 + len + 3) & ~(size_t)3;	/* record, 4-byte aligned */
		/* header word + record, plus an extra length word for big records */
		size_t base = 4 + rec + (rec > MAX_SMALL_RECORD ? 4 : 0);
		uint64_t delta;
		size_t need;
		uint8_t *d;

		/* Refuse anything that could never fit on a page. */
		if (base + 8 > PAGE_DATA || len > 0xffff) {
			free(p->buf);
			p->buf = NULL;
			p->npages = 0;
			errno = EMSGSIZE;
			return -1;
		}

		/* Time since the previous event; clamp to 0 if time went backwards. */
		delta = (page && e->ts_ns > last_ts) ? e->ts_ns - last_ts : 0;
		/* A big gap costs an extra 8-byte time-extend record. */
		need = base + (delta > DELTA_MAX ? 8 : 0);

		/* Start a new page if this is the first event or the page is full. */
		if (!page || used + need > PAGE_DATA) {
			if (page)
				put64(page + 8, used);		/* finalise old page's commit */
			if (pages_grow(p) < 0)
				return -1;
			page = p->buf + (p->npages - 1) * PAGE_SIZE;
			put64(page, e->ts_ns);			/* new page's absolute timestamp */
			last_ts = e->ts_ns;
			used = 0;
			delta = 0;	/* first event on a page is at the page timestamp */
			need = base;
		}

		d = page + PAGE_HDR + used;	/* where this event goes */

		/* 1. Optional time-extend record for gaps that don't fit in 27 bits. */
		if (delta > DELTA_MAX) {
			put32(d, TYPE_TIME_EXTEND | (uint32_t)((delta & DELTA_MAX) << 5));
			put32(d + 4, (uint32_t)(delta >> DELTA_BITS));	/* upper bits */
			d += 8;
			delta = 0;	/* the data event itself adds no more time */
		}

		/* 2. The event header word (and length word for big records). */
		if (rec > MAX_SMALL_RECORD) {
			put32(d, (uint32_t)(delta << 5));	/* type_len 0: length follows */
			put32(d + 4, (uint32_t)(rec + 4));	/* length incl this word */
			d += 8;
		} else {
			put32(d, (uint32_t)(rec / 4) | (uint32_t)(delta << 5));
			d += 4;
		}

		/* 3. The record: common fields, data_loc, then the string. */
		put16(d, TASK_ID);
		d[2] = 0;				/* common_flags */
		d[3] = 0;				/* common_preempt_count */
		put32(d + 4, TASK_PID);
		put32(d + 8, 12u | ((uint32_t)len << 16));	/* string at offset 12 */
		memcpy(d + 12, e->task, len);
		/* Padding bytes after the string are already zero (page was memset). */

		used += need;
		/* The reader's clock never goes backwards; neither may ours. */
		if (e->ts_ns > last_ts)
			last_ts = e->ts_ns;
	}
	if (page)
		put64(page + 8, used);	/* commit of the last page */
	return 0;
}

/* fwrite wrapper: 0 on success, -1 on short write. */
static int wr(FILE *f, const void *data, size_t n)
{
	return fwrite(data, 1, n, f) == n ? 0 : -1;
}

static int wr16(FILE *f, uint16_t v) { return wr(f, &v, sizeof v); }
static int wr32(FILE *f, uint32_t v) { return wr(f, &v, sizeof v); }
static int wr64(FILE *f, uint64_t v) { return wr(f, &v, sizeof v); }

/* u64 length followed by the bytes of s (no terminating NUL). */
static int wr_blob(FILE *f, const char *s)
{
	size_t n = strlen(s);

	return wr64(f, n) || wr(f, s, n);
}

/*
 * Write the whole trace to `path`.
 *
 * The pages are built first so that their total size is known when the
 * "flyrecord" table is written.  The header is a fixed sequence of sections
 * (see the file comment at the top); each `wr*` line below is one field of
 * that sequence.  Errors are accumulated in `err` and checked at the end of
 * each block, which keeps the happy path readable.
 */
int trace_write(const char *path)
{
	/* 3 magic bytes + "tracing" identify a trace.dat file. */
	static const uint8_t magic[10] = { 0x17, 0x08, 0x44, 't', 'r', 'a', 'c', 'i', 'n', 'g' };
	static const uint8_t zero_page[PAGE_SIZE];	/* source of padding bytes */
	struct pages p;
	FILE *f;
	long pos;
	uint64_t data_off, data_size;
	int err = 0;
	int saved;	/* errno is preserved across cleanup calls */

	if (!path) {
		errno = EINVAL;
		return -1;
	}
	if (build_pages(&p) < 0) {
		saved = errno;
		free(p.buf);
		errno = saved;
		return -1;
	}

	f = fopen(path, "wb");
	if (!f) {
		saved = errno;
		free(p.buf);
		errno = saved;
		return -1;
	}

	/* --- fixed header ------------------------------------------------ */
	err |= wr(f, magic, sizeof magic);
	err |= wr(f, "6", 2);			/* version string "6" + NUL */
	err |= wr(f, "\0\x08", 2);		/* 0 = little endian, 8 = sizeof(long) */
	err |= wr32(f, PAGE_SIZE);
	/* Each named section: name with NUL, u64 length, then the text. */
	err |= wr(f, "header_page", 12);
	err |= wr_blob(f, header_page);
	err |= wr(f, "header_event", 13);
	err |= wr_blob(f, header_event);
	err |= wr32(f, 0);			/* number of ftrace event formats: none */
	err |= wr32(f, 1);			/* number of event systems */
	err |= wr(f, "barebox", 8);		/* system name with NUL */
	err |= wr32(f, 1);			/* events in this system */
	err |= wr_blob(f, task_format);
	err |= wr32(f, 0);			/* kallsyms size: none */
	err |= wr32(f, 0);			/* printk formats size: none */
	err |= wr_blob(f, saved_cmdlines);
	err |= wr32(f, 1);			/* number of CPUs */
	err |= wr(f, "options  ", 10);		/* 9 chars + NUL */
	err |= wr16(f, 0);			/* option id 0 = end of options */
	err |= wr(f, "flyrecord", 10);		/* 9 chars + NUL */
	if (err)
		goto fail;

	/* --- CPU data table + padding + pages ---------------------------- */
	pos = ftell(f);
	if (pos < 0)
		goto fail;
	/* The table for 1 CPU is 16 bytes; data starts at the next page boundary. */
	data_off = ((uint64_t)pos + 16 + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
	data_size = (uint64_t)p.npages * PAGE_SIZE;
	err |= wr64(f, data_off);		/* CPU 0: where its pages start */
	err |= wr64(f, data_size);		/* CPU 0: how many bytes */
	err |= wr(f, zero_page, (size_t)(data_off - (uint64_t)pos - 16));
	if (data_size)
		err |= wr(f, p.buf, (size_t)data_size);
	if (err)
		goto fail;
	if (fclose(f) != 0) {
		saved = errno;
		free(p.buf);
		errno = saved;
		return -1;
	}
	free(p.buf);
	return 0;

fail:
	saved = errno;
	fclose(f);
	free(p.buf);
	errno = saved;
	return -1;
}

/* ================================================================== */
/* Part 3: the Perfetto (protobuf) writer                             */
/* ================================================================== */

/*
 * A Perfetto trace is a protobuf "Trace" message streamed to a file: for
 * every TracePacket the file contains the key byte 0x0a (field 1, "packet",
 * length-delimited), the packet length as a varint, and the packet bytes.
 * There is no file header or magic; the 0x0a framing *is* the format.
 *
 * We hand-encode three kinds of TracePacket (field numbers from the proto
 * definitions in perfetto's protos/ tree, all "optional" fields):
 *
 *   1. A ClockSnapshot, so the reader can map our CLOCK_MONOTONIC stamps to
 *      wall time.  It also declares the trace clock to be CLOCK_MONOTONIC
 *      (BuiltinClock 3); without that Perfetto would assume CLOCK_BOOTTIME,
 *      which includes suspend time and can drift from what we recorded.
 *
 *   2. Two TrackDescriptors naming our tracks:
 *        uuid 1 "barebox tasks"   - one instant (point) event per message
 *        uuid 2 "barebox stages"  - one slice per message
 *
 *   3. TrackEvents.  Perfetto has no "complete slice with duration" event,
 *      only BEGIN/END pairs, so message N opens a slice that is closed when
 *      message N+1 arrives (END before BEGIN, so the stages form a sequence
 *      rather than nesting).  The final slice is closed at its own timestamp
 *      and gets duration 0, because the recorder never sees the boot finish.
 *
 * Every event packet carries its own name and category (no interning) and
 * timestamp_clock_id = MONOTONIC, so each packet is self-contained.
 */

/* protobuf wire types */
#define PB_VARINT	0u
#define PB_LEN		2u

/* TracePacket fields */
#define PB_TRUSTED_SEQ_ID	10u	/* uint32, written by the "service" */
#define PB_CLOCK_SNAPSHOT	6u	/* ClockSnapshot */
#define PB_TIMESTAMP		8u	/* uint64, ns */
#define PB_TRACK_EVENT		11u	/* TrackEvent */
#define PB_SEQUENCE_FLAGS	13u	/* bit flags, see SEQ_* below */
#define PB_TS_CLOCK_ID		58u	/* uint32, BuiltinClock */
#define PB_TRACK_DESCRIPTOR	60u	/* TrackDescriptor */

/* TrackEvent fields */
#define TE_TYPE		9u	/* Type enum, see TE_* below */
#define TE_TRACK_UUID	11u	/* uint64 */
#define TE_CATEGORIES	22u	/* repeated string */
#define TE_NAME		23u	/* string */

/* TrackDescriptor fields */
#define TD_UUID		1u
#define TD_NAME		2u

/* ClockSnapshot / Clock fields */
#define CS_CLOCKS	1u	/* repeated Clock */
#define CS_PRIMARY	2u	/* BuiltinClock the trace time runs on */
#define CLK_CLOCK_ID	1u
#define CLK_TIMESTAMP	2u

/* BuiltinClock ids (protos/perfetto/common/builtin_clock.proto) */
#define CLK_REALTIME	1u
#define CLK_MONOTONIC	3u
#define CLK_BOOTTIME	6u

/* TrackEvent.Type */
#define TE_SLICE_BEGIN	1u
#define TE_SLICE_END	2u
#define TE_INSTANT	3u

/* TracePacket.SequenceFlags */
#define SEQ_INCREMENTAL_STATE_CLEARED	1u

/*
 * All packets belong to one writer sequence.  trace_processor needs the
 * id to associate TrackEvents with their incremental state (we keep none,
 * but the association itself is mandatory).
 */
#define SEQ_ID		1u

/* Our two track uuids; 0 is reserved for the implicit trace-global track. */
#define TRACK_TASKS	1u
#define TRACK_STAGES	2u

#define CATEGORY	"barebox"

/*
 * A growable byte buffer used to build one (sub-)message before its length
 * is known.  Allocation failures are sticky in `oom` and surface when the
 * buffer is written out, which keeps the encode helpers return-value-free.
 */
struct pb {
	uint8_t *buf;
	size_t len;
	size_t cap;
	int oom;
};

static void pb_raw(struct pb *b, const void *p, size_t n)
{
	if (b->oom || n == 0)
		return;
	if (b->len + n > b->cap) {
		size_t cap = b->cap ? b->cap * 2 : 128;
		uint8_t *nb;

		while (cap < b->len + n)
			cap *= 2;
		nb = realloc(b->buf, cap);
		if (!nb) {
			b->oom = 1;
			return;
		}
		b->buf = nb;
		b->cap = cap;
	}
	memcpy(b->buf + b->len, p, n);
	b->len += n;
}

static void pb_varint(struct pb *b, uint64_t v)
{
	while (v > 0x7f) {
		uint8_t byte = (uint8_t)v | 0x80;

		pb_raw(b, &byte, 1);
		v >>= 7;
	}
	pb_raw(b, &(uint8_t){ (uint8_t)v }, 1);
}

/* Every protobuf field starts with a key: (field number << 3) | wire type. */
static void pb_key(struct pb *b, unsigned field, unsigned wire)
{
	pb_varint(b, ((uint64_t)field << 3) | wire);
}

static void pb_uint(struct pb *b, unsigned field, uint64_t v)
{
	pb_key(b, field, PB_VARINT);
	pb_varint(b, v);
}

/* Append a nested message: key, its length, then its bytes. */
static void pb_msg(struct pb *b, unsigned field, const struct pb *sub)
{
	pb_key(b, field, PB_LEN);
	pb_varint(b, sub->len);
	pb_raw(b, sub->buf, sub->len);
}

static void pb_str(struct pb *b, unsigned field, const char *s)
{
	size_t n = strlen(s);

	pb_key(b, field, PB_LEN);
	pb_varint(b, n);
	pb_raw(b, s, n);
}

/* Frame one finished TracePacket and write it to the file. */
static int perf_put_packet(FILE *f, const struct pb *pkt)
{
	struct pb frame = { NULL, 0, 0, 0 };
	int err;

	pb_key(&frame, 1, PB_LEN);	/* Trace.packet */
	pb_varint(&frame, pkt->len);
	pb_raw(&frame, pkt->buf, pkt->len);
	err = frame.len ? wr(f, frame.buf, frame.len) : 0;
	free(frame.buf);
	if (frame.oom || pkt->oom) {
		errno = ENOMEM;
		return -1;
	}
	return err;
}

/* Read one clock into nanoseconds. */
static int clock_ns(clockid_t id, uint64_t *out)
{
	struct timespec ts;

	if (clock_gettime(id, &ts) < 0)
		return -1;
	*out = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
	return 0;
}

/*
 * Packet 1 of the trace: the clock snapshot.  Reading CLOCK_MONOTONIC,
 * CLOCK_BOOTTIME and CLOCK_REALTIME almost together gives the reader a
 * mapping between "ns since boot" (what we record), the boot clock
 * (Perfetto's default assumption for proto traces) and wall time (what it
 * displays), and primary_trace_clock tells it our stamps are MONOTONIC.
 */
static int perf_clock_packet(FILE *f)
{
	struct pb mono = { NULL, 0, 0, 0 }, boot = { NULL, 0, 0, 0 };
	struct pb real = { NULL, 0, 0, 0 }, snap = { NULL, 0, 0, 0 };
	struct pb pkt = { NULL, 0, 0, 0 };
	uint64_t m, b, r;
	int err;

	if (clock_ns(CLOCK_MONOTONIC, &m) < 0 ||
	    clock_ns(CLOCK_BOOTTIME, &b) < 0 ||
	    clock_ns(CLOCK_REALTIME, &r) < 0)
		return -1;

	pb_uint(&mono, CLK_CLOCK_ID, CLK_MONOTONIC);
	pb_uint(&mono, CLK_TIMESTAMP, m);
	pb_uint(&boot, CLK_CLOCK_ID, CLK_BOOTTIME);
	pb_uint(&boot, CLK_TIMESTAMP, b);
	pb_uint(&real, CLK_CLOCK_ID, CLK_REALTIME);
	pb_uint(&real, CLK_TIMESTAMP, r);
	pb_msg(&snap, CS_CLOCKS, &mono);
	pb_msg(&snap, CS_CLOCKS, &boot);
	pb_msg(&snap, CS_CLOCKS, &real);
	pb_uint(&snap, CS_PRIMARY, CLK_MONOTONIC);

	pb_uint(&pkt, PB_TRUSTED_SEQ_ID, SEQ_ID);
	pb_uint(&pkt, PB_SEQUENCE_FLAGS, SEQ_INCREMENTAL_STATE_CLEARED);
	pb_msg(&pkt, PB_CLOCK_SNAPSHOT, &snap);

	err = perf_put_packet(f, &pkt);
	free(mono.buf);
	free(boot.buf);
	free(real.buf);
	free(snap.buf);
	free(pkt.buf);
	return err;
}

/* One packet describing a track by uuid + name. */
static int perf_track_packet(FILE *f, uint64_t uuid, const char *name)
{
	struct pb td = { NULL, 0, 0, 0 }, pkt = { NULL, 0, 0, 0 };
	int err;

	pb_uint(&td, TD_UUID, uuid);
	pb_str(&td, TD_NAME, name);
	pb_uint(&pkt, PB_TRUSTED_SEQ_ID, SEQ_ID);
	pb_msg(&pkt, PB_TRACK_DESCRIPTOR, &td);
	err = perf_put_packet(f, &pkt);
	free(td.buf);
	free(pkt.buf);
	return err;
}

/*
 * One TrackEvent packet.  `name` is NULL for slice ends, which just close
 * the innermost open slice on the track and repeat nothing else.
 */
static int perf_event_packet(FILE *f, uint64_t ts_ns, unsigned type,
			     uint64_t track, const char *name)
{
	struct pb ev = { NULL, 0, 0, 0 }, pkt = { NULL, 0, 0, 0 };
	int err;

	pb_uint(&ev, TE_TYPE, type);
	pb_uint(&ev, TE_TRACK_UUID, track);
	if (name) {
		pb_str(&ev, TE_CATEGORIES, CATEGORY);
		pb_str(&ev, TE_NAME, name);
	}
	pb_uint(&pkt, PB_TRUSTED_SEQ_ID, SEQ_ID);
	pb_uint(&pkt, PB_TIMESTAMP, ts_ns);
	pb_uint(&pkt, PB_TS_CLOCK_ID, CLK_MONOTONIC);
	pb_msg(&pkt, PB_TRACK_EVENT, &ev);
	err = perf_put_packet(f, &pkt);
	free(ev.buf);
	free(pkt.buf);
	return err;
}

/*
 * Write all entries to `path` as a Perfetto trace, openable with
 * ui.perfetto.dev ("Open with trace file") or queryable with
 * trace_processor ("select * from slice" / "instant").  An empty list
 * produces a valid trace with no events.
 */
int trace_write_perfetto(const char *path)
{
	const struct entry *e;
	FILE *f;
	int saved;

	if (!path) {
		errno = EINVAL;
		return -1;
	}
	f = fopen(path, "wb");
	if (!f)
		return -1;

	if (perf_clock_packet(f) < 0)
		goto fail;
	if (perf_track_packet(f, TRACK_TASKS, "barebox tasks") < 0)
		goto fail;
	if (perf_track_packet(f, TRACK_STAGES, "barebox stages") < 0)
		goto fail;

	for (e = head; e; e = e->next) {
		/* At a new message, the previous stage is over: end before
		 * begin, so equal timestamps do not make the slices nest. */
		if (e != head &&
		    perf_event_packet(f, e->ts_ns, TE_SLICE_END, TRACK_STAGES, NULL) < 0)
			goto fail;
		if (perf_event_packet(f, e->ts_ns, TE_SLICE_BEGIN, TRACK_STAGES, e->task) < 0)
			goto fail;
		if (perf_event_packet(f, e->ts_ns, TE_INSTANT, TRACK_TASKS, e->task) < 0)
			goto fail;
	}
	/* The last stage's end is never observed; close it where it began. */
	if (tail && perf_event_packet(f, tail->ts_ns, TE_SLICE_END, TRACK_STAGES, NULL) < 0)
		goto fail;

	if (fclose(f) != 0)
		return -1;
	return 0;

fail:
	saved = errno;
	fclose(f);
	errno = saved;
	return -1;
}
