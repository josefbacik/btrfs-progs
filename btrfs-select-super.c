/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
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
#include "print-tree.h"
#include "transaction.h"
#include "list.h"
#include "version.h"
#include "utils.h"

static void print_usage(void)
{
	fprintf(stderr, "usage: btrfs-select-super [-c] [-e] -s number dev\n");
	fprintf(stderr, "       -c Commit changes to disk [IRREVERSIBLE]\n");
	fprintf(stderr, "       -e Use the earliest super found, may help recover transid verify problems\n");
	fprintf(stderr, "%s\n", BTRFS_BUILD_VERSION);
	exit(1);
}

int main(int ac, char **av)
{
	struct btrfs_root *root;
	int ret;
	int num;
	u64 bytenr = 0;
	int commit = 0;
	int use_earliest_bdev = 0;
	int fp;

	while(1) {
		int c;
		c = getopt(ac, av, "s:ce");
		if (c < 0)
			break;
		switch(c) {
			case 's':
				num = atol(optarg);
				bytenr = btrfs_sb_offset(num);
				printf("using SB copy %d, bytenr %llu\n", num,
				       (unsigned long long)bytenr);
				break;
			case 'c':
				commit = 1;
				break;
			case 'e':
				use_earliest_bdev = 1;
				break;
			default:
				print_usage();
		}
	}
	ac = ac - optind;

	if (ac != 1)
		print_usage();

	if (bytenr == 0) {
		fprintf(stderr, "Please select the super copy with -s\n");
		print_usage();
	}

	radix_tree_init();

	if ((ret = check_mounted(av[optind])) < 0) {
		fprintf(stderr, "Could not check mount status: %s\n", strerror(-ret));
		return ret;
	} else if (ret) {
		fprintf(stderr, "%s is currently mounted. Aborting.\n", av[optind]);
		return -EBUSY;
	}

	fp = open(av[optind], O_CREAT|O_RDWR, 0600);
	if (fp < 0) {
		fprintf(stderr, "Could not open %s\n", av[optind]);
		return 1;
	}
	root = open_ctree_fd(fp, av[optind], bytenr, 1, use_earliest_bdev);

	if (root == NULL)
		return 1;

	fprintf(stderr, "Found superblock with generation %llu.\n", root->fs_info->super_copy.generation);

	if (commit) {
		fprintf(stderr, "Committing...\n");

		/* make the super writing code think we've read the first super */
		root->fs_info->super_bytenr = BTRFS_SUPER_INFO_OFFSET;
		ret = write_all_supers(root);
	}

	/* we don't close the ctree or anything, because we don't want a real
	 * transaction commit.  We just want the super copy we pulled off the
	 * disk to overwrite all the other copies
	 */ 
	return ret;
}
