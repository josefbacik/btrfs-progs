/*
 * Copyright (C) 2011 Red Hat.  All rights reserved.
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
#include <zlib.h>
#include "kerncompat.h"
#include "ctree.h"
#include "disk-io.h"
#include "print-tree.h"
#include "transaction.h"
#include "list.h"
#include "version.h"
#include "volumes.h"
#include "utils.h"
#include "crc32c.h"

static int verbose = 0;
static u16 csum_size = 0;
static u64 search_objectid = BTRFS_ROOT_TREE_OBJECTID;

static void usage()
{
	fprintf(stderr, "Usage: find-roots [-v] <device>\n");
}

int csum_block(void *buf, u32 len)
{
	char *result;
	u32 crc = ~(u32)0;
	int ret = 0;

	result = malloc(csum_size * sizeof(char));
	if (!result) {
		fprintf(stderr, "No memory\n");
		return 1;
	}

	len -= BTRFS_CSUM_SIZE;
	crc = crc32c(crc, buf + BTRFS_CSUM_SIZE, len);
	btrfs_csum_final(crc, result);

	if (memcmp(buf, result, csum_size))
		ret = 1;
	free(result);
	return ret;
}

static int __setup_root(u32 nodesize, u32 leafsize, u32 sectorsize,
			u32 stripesize, struct btrfs_root *root,
			struct btrfs_fs_info *fs_info, u64 objectid)
{
	root->node = NULL;
	root->commit_root = NULL;
	root->sectorsize = sectorsize;
	root->nodesize = nodesize;
	root->leafsize = leafsize;
	root->stripesize = stripesize;
	root->ref_cows = 0;
	root->track_dirty = 0;

	root->fs_info = fs_info;
	root->objectid = objectid;
	root->last_trans = 0;
	root->highest_inode = 0;
	root->last_inode_alloc = 0;

	INIT_LIST_HEAD(&root->dirty_list);
	memset(&root->root_key, 0, sizeof(root->root_key));
	memset(&root->root_item, 0, sizeof(root->root_item));
	root->root_key.objectid = objectid;
	return 0;
}

static int dump_root_bytenr(struct btrfs_root *root, u64 bytenr, u64 gen)
{
	struct btrfs_root *tmp = malloc(sizeof(struct btrfs_root));
	struct btrfs_path *path;
	struct btrfs_key key;
	struct btrfs_root_item ri;
	struct extent_buffer *leaf;
	struct btrfs_disk_key disk_key;
	struct btrfs_key found_key;
	int slot;
	int ret;

	if (!tmp)
		return -ENOMEM;

	__setup_root(4096, 4096, 4096, 4096, tmp,
		     root->fs_info, BTRFS_ROOT_TREE_OBJECTID);

	tmp->node = read_tree_block(root, bytenr, 4096, gen);

	key.objectid = 0;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = -1;

	path = btrfs_alloc_path();

	/* Walk the slots of this root looking for BTRFS_ROOT_ITEM_KEYs. */
	ret = btrfs_search_slot(NULL, tmp, &key, path, 0, 0);
	BUG_ON(ret < 0);
	while (1) {
		leaf = path->nodes[0];
		slot = path->slots[0];
		if (slot >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(tmp, path);
			if (ret != 0)
				break;
			leaf = path->nodes[0];
			slot = path->slots[0];
		}
		btrfs_item_key(leaf, &disk_key, path->slots[0]);
		btrfs_disk_key_to_cpu(&found_key, &disk_key);
		if (btrfs_key_type(&found_key) == BTRFS_ROOT_ITEM_KEY) {
			unsigned long offset;

			offset = btrfs_item_ptr_offset(leaf, slot);
			read_extent_buffer(leaf, &ri, offset, sizeof(ri));
			printf("Generation: %Lu Root bytenr: %Lu "
			       "Root objectid: %Lu\n", gen,
			       btrfs_root_bytenr(&ri), found_key.objectid);
		}
		path->slots[0]++;
	}
	btrfs_free_path(path);
	free_extent_buffer(leaf);
	return 0;
}

static int search_iobuf(struct btrfs_root *root, void *iobuf,
                        size_t iobuf_size, off_t offset)
{
	u64 gen = btrfs_super_generation(&root->fs_info->super_copy);
	u64 objectid = search_objectid;
	u32 size = btrfs_super_nodesize(&root->fs_info->super_copy);
	u8 level = root->fs_info->super_copy.root_level;
	size_t block_off = 0;

	while (block_off < iobuf_size) {
		void *block = iobuf + block_off;
		struct btrfs_header *header = block;
		u64 h_byte, h_level, h_gen, h_owner;

//		printf("searching %Lu\n", offset + block_off);
		h_byte = le64_to_cpu(header->bytenr);
		h_owner = le64_to_cpu(header->owner);
		h_level = header->level;
		h_gen = le64_to_cpu(header->generation);

		if (h_owner != objectid)
			goto next;
		if (h_byte != (offset + block_off))
			goto next;
		if (h_level != level)
			goto next;
		if (csum_block(block, size)) {
			fprintf(stderr, "Well block %Lu seems good, "
				"but the csum doesn't match\n",
				h_byte);
			goto next;
		}
		/* Found some kind of root and it's fairly valid. */
		if (dump_root_bytenr(root, h_byte, h_gen))
		        break;
		if (h_gen != gen) {
			fprintf(stderr, "Well block %Lu seems great, "
				"but generation doesn't match, "
				"have=%Lu, want=%Lu\n", h_byte, h_gen,
				gen);
			goto next;
		}
		printf("Found tree root at %Lu\n", h_byte);
		return 0;
next:
		block_off += size;
	}

	return 1;
}

static int read_physical(struct btrfs_root *root, int fd, u64 offset,
			 u64 bytenr, u64 len)
{
	char *iobuf = malloc(len);
	ssize_t done;
	size_t total_read = 0;
	int ret = 1;

	if (!iobuf) {
		fprintf(stderr, "No memory\n");
		return -1;
	}

	while (total_read < len) {
		done = pread64(fd, iobuf + total_read, len - total_read,
			       bytenr + total_read);
		if (done < 0) {
			fprintf(stderr, "Failed to read: %s\n",
				strerror(errno));
			ret = -1;
			goto out;
		}
		total_read += done;
	}

	ret = search_iobuf(root, iobuf, total_read, offset);
out:
	free(iobuf);
	return ret;
}

static int find_root(struct btrfs_root *root)
{
	struct btrfs_multi_bio *multi = NULL;
	struct btrfs_device *device;
	u64 metadata_offset = 0, metadata_size = 0;
	off_t offset = 0;
	off_t bytenr;
	int fd;
	int err;
	int ret = 1;

	printf("Super think's the tree root is at %Lu, chunk root %Lu\n",
	       btrfs_super_root(&root->fs_info->super_copy),
	       btrfs_super_chunk_root(&root->fs_info->super_copy));

	err = btrfs_next_metadata(&root->fs_info->mapping_tree,
				  &metadata_offset, &metadata_size);
	if (err)
		return ret;

	offset = metadata_offset;
	if (verbose)
		printf("Checking metadata chunk %Lu, size %Lu\n",
		       metadata_offset, metadata_size);

	while (1) {
		u64 map_length = 4096;
		u64 type;
		int mirror_num;
		int num_copies;

		if (offset >= (metadata_offset + metadata_size)) {
			if (verbose)
				printf("Moving to the next metadata chunk\n");
			err = btrfs_next_metadata(&root->fs_info->mapping_tree,
						  &metadata_offset,
						  &metadata_size);
			if (err) {
				printf("No more metdata to scan, exiting\n");
				break;
			}
			offset = metadata_offset;
			if (verbose)
				printf("Checking metadata chunk %Lu, size %Lu"
				       "\n", metadata_offset, metadata_size);
		}
		mirror_num = 1;
	again:
		err = __btrfs_map_block(&root->fs_info->mapping_tree, READ,
				      offset, &map_length, &type, &multi, mirror_num);
		if (err) {
			offset += map_length;
			continue;
		}

		if (!(type & BTRFS_BLOCK_GROUP_METADATA)) {
			offset += map_length;
			continue;
		}

		device = multi->stripes[0].dev;
		fd = device->fd;
		bytenr = multi->stripes[0].physical;
		kfree(multi);

		err = read_physical(root, fd, offset, bytenr, map_length);
		if (!err) {
			/* Found the root. */
			ret = 0;
			break;
		} else if (err < 0) {
			num_copies = btrfs_num_copies(&root->fs_info->mapping_tree,
						      offset, map_length);
			mirror_num++;
			if (mirror_num <= num_copies)
				goto again;
			/* Unrecoverable error in read. */
			ret = err;
			break;
		}
		offset += map_length;
	}
	return ret;
}

int main(int argc, char **argv)
{
	struct btrfs_root *root;
	int dev_fd;
	int opt;
	int ret;

	while ((opt = getopt(argc, argv, "vo:")) != -1) {
		switch(opt) {
			case 'v':
				verbose++;
				break;
			case 'o':
				errno = 0;
				search_objectid = (u64)strtoll(optarg, NULL,
							       10);
				if (errno) {
					fprintf(stderr, "Error parsing "
						"objectid\n");
					exit(1);
				}
				break;
			default:
				usage();
				exit(1);
		}
	}

	if (optind >= argc) {
		usage();
		exit(1);
	}

	dev_fd = open(argv[optind], O_RDONLY);
	if (dev_fd < 0) {
		fprintf(stderr, "Failed to open device %s\n", argv[optind]);
		exit(1);
	}

	root = open_ctree_broken(dev_fd, argv[optind]);
	close(dev_fd);
	if (!root)
		exit(1);

	csum_size = btrfs_super_csum_size(&root->fs_info->super_copy);
	ret = find_root(root);
	close_ctree(root);
	return ret;
}
