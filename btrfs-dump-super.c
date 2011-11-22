/*
 * Copyright (C) 2011 Google.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#define _XOPEN_SOURCE 500
#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "kerncompat.h"
#include "ctree.h"
#include "disk-io.h"
#include "version.h"

static void print_usage(void)
{
	fprintf(stderr, "usage: btrfs-dump-super dev\n");
	fprintf(stderr, "%s\n", BTRFS_BUILD_VERSION);
	exit(1);
}

static int read_block(const char* filename,  u64 bytenr, struct btrfs_super_block* sb) {
	int fd = open(filename, O_RDONLY, 0600);
	int block_size = sizeof(struct btrfs_super_block);
	int bytes_read = 0;

	if (fd < 0) {
		fprintf(stderr, "Could not open %s\n", filename);
		return -1;
	}

	bytes_read = pread(fd, sb, block_size, bytenr);
	if (bytes_read < block_size) {
		fprintf(stderr, "Only read %d bytes of %d.\n", bytes_read, block_size);
	}

	close(fd);
	return bytes_read;
}

int main(int ac, char **av)
{
	int i;

	if (ac != 2)
		print_usage();

	for (i = 0; i < BTRFS_SUPER_MIRROR_MAX; i++) {
		u64 bytenr = btrfs_sb_offset(i);
		int fd;
		struct btrfs_super_block sb;
		int block_size = sizeof(struct btrfs_super_block);
		char filename[1024];
		int bytes_read = read_block(av[optind], bytenr, &sb);
		if (bytes_read < block_size)
			continue;

		sprintf(filename, "/tmp/block.%s.%llu",
			strrchr(av[optind], '/') + 1, bytenr);
		fd = open(filename, O_CREAT|O_WRONLY, 0644);
		if (block_size != pwrite(fd, &sb, block_size, 0)) {
			fprintf(stderr, "Failed to dump superblock %d", i);
			continue;
		}
		fprintf(stderr, "Dumped superblock %s:%d, gen %llu to %s.\n",
			av[optind], i, sb.generation, filename);
		close(fd);
	}

	return 0;
}
