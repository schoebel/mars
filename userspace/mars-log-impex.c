/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
 *
 * Copyright (C) 2010-2014 Thomas Schoebel-Theuer
 * Copyright (C) 2011-2014 1&1 Internet AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


/* This is PROVISIONARY hacker's tool for import / export
 * of MARS transaction logfiles.
 *
 * NOT FOR END USERS!!!!!
 */
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <time.h>

/* FIXME: some _provisionary_ hacks to bridge the gap between kernelspace and userspace...
 */
#define bool int
#define false 0
#define true 1
#define likely(x) x
#define unlikely(x) x
#define MARS_INF printf
#define MARS_WRN printf
#define MARS_ERR printf
#define mars_digest_size 16
#define mars_digest(a,b,c) /*empty*/
#define loff_t long long
#define scnprintf snprintf
#include "../kernel/lib_log.h"

static
int read_record(
	struct log_header *lh,
	void *buf,
	int maxlen,
	int fh,
	loff_t pos,
	void **payload,
	int *payload_len,
	unsigned int *seq_nr)
{
	ssize_t status;

	status = pread(fh, buf, maxlen, pos);
	if (status < 0) {
		MARS_ERR("cannot pread() %d bytes, status = %d\n", maxlen, (int)status);
		return -errno;
	}
	if (!status) {
		MARS_INF("got EOF\n");
		return 0;
	}

	return log_scan(buf, status, pos, 0, true, lh, payload, payload_len, seq_nr);
}

static
int write_record(
	int out_fd,
	void *buf,
	int buf_len,
	char *desc)
{
	struct log_header lh = {
		.l_len = buf_len,
	};
	unsigned short total_len = buf_len + OVERHEAD;
	char data[total_len];
	int offset = 0;
	int len = strlen(desc);
	int crc = 0;
	int status;

	// extract filename from desc path
	while (len > 0 && desc[len-1] != '/')
		len--;
	desc += len;

	status = sscanf(
		desc,
		"%u,%ld.%lu,%ld.%lu,%hx,%lld",
		&lh.l_seq_nr,
		&lh.l_stamp.tv_sec,
		&lh.l_stamp.tv_nsec,
		&lh.l_written.tv_sec,
		&lh.l_written.tv_nsec,
		&lh.l_code,
		&lh.l_pos
		);
	if (status != 7) {
		MARS_ERR("only %d arguments parsable from '%s'\n", status, desc);
		return -EINVAL;
	}
	
	DATA_PUT(data, offset, START_MAGIC);
	DATA_PUT(data, offset, (char)FORMAT_VERSION);
	DATA_PUT(data, offset, (char)1); // valid_flag
	DATA_PUT(data, offset, total_len); // start of next header
	DATA_PUT(data, offset, lh.l_stamp.tv_sec);
	DATA_PUT(data, offset, lh.l_stamp.tv_nsec);
	DATA_PUT(data, offset, lh.l_pos);
	DATA_PUT(data, offset, lh.l_len);
	DATA_PUT(data, offset, (short)0); // spare
	DATA_PUT(data, offset, (int)0); // spare
	DATA_PUT(data, offset, lh.l_code);
	DATA_PUT(data, offset, (short)0); // spare

	memcpy(data + offset, buf, buf_len);
	offset += buf_len;

	DATA_PUT(data, offset, END_MAGIC);
	DATA_PUT(data, offset, crc);
	DATA_PUT(data, offset, (char)1);  // valid_flag copy
	DATA_PUT(data, offset, (char)0);  // spare
	DATA_PUT(data, offset, (short)0); // spare
	DATA_PUT(data, offset, lh.l_seq_nr);
	DATA_PUT(data, offset, lh.l_written.tv_sec);  
	DATA_PUT(data, offset, lh.l_written.tv_nsec);

	if (offset != total_len) {
		MARS_ERR("offset %d != total_len %d\n", offset, total_len);
		return -EINVAL;
	}

	status = write(out_fd, data, total_len);
	if (status != total_len) {
		MARS_ERR("bad write, status = %d errno = %d\n", status, errno);
		return -EIO;
	}

	return 0;
}

static
int make_dirs(char *out, int out_len, char *out_dirname, int old[], unsigned int seqnr)
{
	int len;
	unsigned int nr;
	
	nr = seqnr / 1000000000;
	
	len = scnprintf(out, out_len, "%s/%01u", out_dirname, nr);

	if (old[0] != nr) {
		old[0] = nr;
		(void)mkdir(out, 0700);
	}

	nr = seqnr / 1000000 % 1000;

	len += scnprintf(out + len, out_len - len, "/%03u", nr);

	if (old[1] != nr) {
		old[1] = nr;
		(void)mkdir(out, 0700);
	}

	nr = seqnr / 1000 % 1000;

	len += scnprintf(out + len, out_len - len, "/%03u", nr);

	if (old[2] != nr) {
		old[2] = nr;
		(void)mkdir(out, 0700);
	}

	return len;
}

static
int export_logfile(char *in_filename, char *out_dirname)
{
	char buf[4096 * 8];
	int old[3] = { -1, -1, -1};
	loff_t pos = 0;
	unsigned int old_seqnr = 0;
	int in_fd;

	in_fd = open(in_filename, O_RDONLY);
	if (in_fd < 0) {
		MARS_ERR("cannot open input file '%s', errno = %d\n", in_filename, errno);
		return -errno;
	}

	if (out_dirname) {
		(void)mkdir(out_dirname, 0700);
	}

	for (;;) {
		struct log_header lh = {};
		void *payload = NULL;
		int payload_len = 0;
		unsigned int seqnr = 0;
		int status;

		status = read_record(&lh, buf, sizeof(buf), in_fd, pos, &payload, &payload_len, &seqnr);
		if (status <= 0) {
			return status;
		}

		if (old_seqnr > 0 && seqnr != old_seqnr + 1) {
			printf("ERROR: seqnr = %d status = %d\n", seqnr, status);
		} else {
			//printf("OK: seqnr = %d status = %d\n", seqnr, status);
		}

		if (out_dirname) {
			char out_name[1024];
			int len;
			int out_fd;

			len = make_dirs(out_name, sizeof(out_name), out_dirname, old, seqnr);
			
			snprintf(out_name + len, sizeof(out_name) - len,
				 "/%010u,%09u.%09u,%09u.%09u,%04x,%012llu",
				 seqnr,
				 (unsigned)lh.l_stamp.tv_sec,
				 (unsigned)lh.l_stamp.tv_nsec,
				 (unsigned)lh.l_written.tv_sec,
				 (unsigned)lh.l_written.tv_nsec,
				 lh.l_code,
				 (unsigned long long)lh.l_pos
				);

			out_fd = creat(out_name, 0600);
			if (out_fd < 0) {
				MARS_ERR("cannot open output file '%s', errno = %d\n", out_name, errno);
				return -errno;
			}
			write(out_fd, payload, payload_len);
			close(out_fd);
		}

		pos += status;
		old_seqnr = seqnr;
	}
}

static
int import_logfile(char *in_dirname, char *out_filename)
{
	char buf[4096 * 8];
	char cmd[256];
	int out_fd;
	FILE *names;

	snprintf(cmd, sizeof(cmd), "find '%s' -type f -name '[0-9]*[0-9]' | sort -n", in_dirname);

	names = popen(cmd, "r");
	if (!names) {
		MARS_ERR("cannot popen command '%s', errno = %d\n", cmd, errno);
		return -errno;
	}

	out_fd = creat(out_filename, 0600);
	if (out_fd < 0) {
		MARS_ERR("cannot open output file '%s', errno = %d\n", out_filename, errno);
		return -errno;
	}

	for (;;) {
		char path[1024];
		int len;
		int in_fd;
		int status;

		if (!fgets(path, sizeof(path), names)) {
			break;
		}
		// chomp the terminating \n
		len = strlen(path);
		if (len <= 1)
			continue;
		if (path[len-1] == '\n')
			path[len-1] = '\0';

		in_fd = open(path, O_RDONLY);
		if (in_fd < 0) {
			MARS_ERR("cannot open input file '%s', errno = %d\n", path, errno);
			return -errno;
		}

		status = read(in_fd, buf, sizeof(buf));
		if (status < 0) {
			MARS_ERR("cannot read from input file '%s', errno = %d\n", path, errno);
			return -errno;
		}
		close(in_fd);
		if (status >= sizeof(buf)) {
			MARS_ERR("input file '%s' contains a too long record\n", path);
			return -EINVAL;
		}

		printf("record '%s' len = %d\n", path, status);
		status = write_record(out_fd, buf, status, path);
		if (status < 0)
			break;
	}

	close(out_fd);
	pclose(names);
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 3) {
		printf("usage: mars-log-impex {im,ex}port filename [dirname]\n");
		return -1;
	}

	if (!strcmp(argv[1], "export")) {
		char *out_dirname = NULL;
		if (argc > 3 && argv[3])
			out_dirname = argv[3];
		return export_logfile(argv[2], out_dirname);
	}
	if (!strcmp(argv[1], "import") && argc > 3) {
		return import_logfile(argv[3], argv[2]);
	}

	return 0;
}
