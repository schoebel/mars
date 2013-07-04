// (c) 2013 Thomas Schoebel-Theuer / 1&1 Internet AG

/* This is a trivial hacker's tool for testing the reboot saftey of MARS
 * (or other system software).
 *
 * The trick is to reboot _immediately_ after the last IO operation.
 * Will the block layer contain _all_ the data, at least if it had been
 * sync()ed before?
 *
 * Note: the transaction logfiles of MARS may contain an incomplete
 * log record at the end if there was (additional) IO running _in parallel_
 * to the reboot operation.
 * Even then, the transaction logfile must contain all the data which
 * has been reported as "completed" by O_DIRECT or O_SYNC or by one
 * of the fsync() / fdatasync() operations.
 * In addition, MARS must tolerate such incomplete records because they
 * are unavoidable as such (races between IO and reboot / reset).
 *
 * Exception: when /proc/sys/mars/logger_completion_semantics is deliberately
 * set to 0, some synced IO may get lost. However, even then the _order_ must
 * be correct.
 *
 * Hint: you may also try physical reset via IPMI
 */

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>

#include <linux/reboot.h>
#include <sys/reboot.h>

#include <time.h>

#define BLK_SIZE 1024

static
time_t now = 0;

static
int blk_size = BLK_SIZE;

void write_block(int fd, int nr)
{
	char *buf = aligned_alloc(blk_size, blk_size);
	int status;

	if (!buf) {
		fprintf(stderr, "no mem\n");
		exit (-1);
	}

	/* Hint: you may simply use the tool "strings" to dig for
	 * the markers produced by this.
	 * When running multiple times, check the correctness of the
	 * timestamps.
	 */
	memset(buf, 0, blk_size);
	snprintf(buf, blk_size, "timestamp %lld block %05d\n", (long long)now, nr);

	status = write(fd, buf, blk_size);
	if (status != blk_size) {
		fprintf(stderr, "write() #%d failed, status = %d, errno = %d %s\n", nr, status, errno, strerror(errno));
		exit (-1);
	}

	free(buf);
}

int main(int argc, char *argv[])
{
	/* smode:
	 *  0 = only write blocks (see fmode)            [DEFAULT]
	 *  1 = immedialtely reboot afterwards (no sync, no pause)
	 *  2 = use fdatasync() before reboot
	 *  3 = use fsync() before reboot
	 */
	int smode = 0;

	/* fmode:
	 *  0 = buffered write (IO may get lost because of buffering)
	 *  1 = use O_DIRECT   (IO should not get lost)  [DEFAULT]
	 *  2 = use O_SYNC     (IO should not get lost)
	 * [combine the bits like a bitmask]
	 */
	int fmode = 1;
	int flags = O_WRONLY | O_CREAT;

	int count = 1000;
	int fd;
	int i;

	if (argc < 2) {
		fprintf(stderr, "usage: write-reboot <filename> [<smode>] [<fmode>] [<count>] [<blk_size>]\n");
		exit (-1);
	}
	if (argc > 2) {
		smode = atoi(argv[2]);
	}
	if (argc > 3) {
		fmode = atoi(argv[3]);
	}
	if (fmode & 1)
		flags |= O_DIRECT;
	if (fmode & 2)
		flags |= O_SYNC;
	if (argc > 4) {
		count = atoi(argv[4]);
	}
	if (argc > 5) {
		blk_size = atoi(argv[5]);
	}

	time(&now);

	printf("now = %lld file = '%s' fmode = %d smode = %d count = %d blk_size = %d\n",
	       (long long)now,
	       argv[1],
	       fmode,
	       smode,
	       count,
	       blk_size);

	fd = open(argv[1], flags,  0600);
	if (fd < 0) {
		fprintf(stderr, "open() with flags %d failed, errno = %d %s\n", flags, errno, strerror(errno));
		exit (-1);
	}
	printf("fd = %d\n", fd);

	for (i = 0; i < count; i++) {
		write_block(fd, i);
	}
	
	printf("done.\n");

	if (smode > 2) {
		printf("fsync()\n");
		fsync(fd);
	} else
	if (smode > 1) {
		printf("fdatasync()\n");
		fdatasync(fd);
	}

	if (smode > 0) {
		printf("reboot...\n");
		reboot(LINUX_REBOOT_CMD_RESTART);
	}

	return 0;
}
