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

static char path_name[4096];
static int get_snaps = 0;

static int decompress(char *inbuf, char *outbuf, u64 compress_len,
		      u64 decompress_len)
{
	z_stream strm;
	int ret;

	memset(&strm, 0, sizeof(strm));
	ret = inflateInit(&strm);
	if (ret != Z_OK) {
		fprintf(stderr, "inflate init returnd %d\n", ret);
		return -1;
	}

	strm.avail_in = compress_len;
	strm.next_in = (unsigned char *)inbuf;
	strm.avail_out = decompress_len;
	strm.next_out = (unsigned char *)outbuf;
	ret = inflate(&strm, Z_NO_FLUSH);
	if (ret != Z_STREAM_END) {
		(void)inflateEnd(&strm);
		fprintf(stderr, "ret is %d\n", ret);
		return -1;
	}

	(void)inflateEnd(&strm);
	return 0;
}

static int copy_one_inline(int fd, struct btrfs_path *path, u64 pos)
{
	struct extent_buffer *leaf = path->nodes[0];
	struct btrfs_file_extent_item *fi;
	char buf[4096];
	char *outbuf;
	ssize_t done;
	unsigned long ptr;
	int ret;
	int len;
	int ram_size;
	int compress;

	fi = btrfs_item_ptr(leaf, path->slots[0],
			    struct btrfs_file_extent_item);
	ptr = btrfs_file_extent_inline_start(fi);
	len = btrfs_file_extent_inline_item_len(leaf,
					btrfs_item_nr(leaf, path->slots[0]));
	read_extent_buffer(leaf, buf, ptr, len);

	compress = btrfs_file_extent_compression(leaf, fi);
	if (compress == BTRFS_COMPRESS_NONE) {
		done = pwrite(fd, buf, len, pos);
		if (done < len) {
			fprintf(stderr, "Short write: %d\n", errno);
			return -1;
		}
		return 0;
	}

	ram_size = btrfs_file_extent_ram_bytes(leaf, fi);
	outbuf = malloc(ram_size);
	if (!outbuf) {
		fprintf(stderr, "No memory\n");
		return -1;
	}

	ret = decompress(buf, outbuf, len, ram_size);
	if (ret) {
		free(outbuf);
		return ret;
	}

	done = pwrite(fd, outbuf, ram_size, pos);
	free(outbuf);
	if (done < len) {
		fprintf(stderr, "Short write: %d\n", errno);
		return -1;
	}

	return 0;
}

static int copy_one_extent(struct btrfs_root *root, int fd,
			   struct extent_buffer *leaf,
			   struct btrfs_file_extent_item *fi, u64 pos)
{
	struct btrfs_multi_bio *multi = NULL;
	struct btrfs_device *device;
	char *inbuf, *outbuf = NULL;
	ssize_t done;
	u64 bytenr;
	u64 ram_size;
	u64 disk_size;
	u64 length;
	u64 size_left;
	u64 dev_bytenr;
	u64 count = 0;
	int compress;
	int ret;
	int dev_fd;

	compress = btrfs_file_extent_compression(leaf, fi);
	bytenr = btrfs_file_extent_disk_bytenr(leaf, fi);
	disk_size = btrfs_file_extent_disk_num_bytes(leaf, fi);
	ram_size = btrfs_file_extent_ram_bytes(leaf, fi);
	size_left = disk_size;

	inbuf = malloc(disk_size);
	if (!inbuf) {
		fprintf(stderr, "No memory\n");
		return -1;
	}

	if (compress != BTRFS_COMPRESS_NONE) {
		outbuf = malloc(ram_size);
		if (!outbuf) {
			fprintf(stderr, "No memory\n");
			free(inbuf);
			return -1;
		}
	}
again:
	length = size_left;
	ret = btrfs_map_block(&root->fs_info->mapping_tree, READ,
			      bytenr, &length, &multi, 0);
	if (ret) {
		free(inbuf);
		free(outbuf);
		fprintf(stderr, "Error mapping block %d\n", ret);
		return ret;
	}
	device = multi->stripes[0].dev;
	dev_fd = device->fd;
	device->total_ios++;
	dev_bytenr = multi->stripes[0].physical;
	kfree(multi);

	if (size_left < length)
		length = size_left;
	size_left -= length;

	done = pread(dev_fd, inbuf+count, length, dev_bytenr);
	if (done < length) {
		free(inbuf);
		free(outbuf);
		fprintf(stderr, "Short read %d\n", errno);
		return -1;
	}

	count += length;
	bytenr += length;
	if (size_left)
		goto again;


	if (compress == BTRFS_COMPRESS_NONE) {
		done = pwrite(fd, inbuf, ram_size, pos);
		free(inbuf);
		if (done < ram_size) {
			fprintf(stderr, "Short write: %d\n", errno);
			return -1;
		}
		return 0;
	}

	ret = decompress(inbuf, outbuf, disk_size, ram_size);
	free(inbuf);
	if (ret) {
		free(outbuf);
		return ret;
	}

	done = pwrite(fd, outbuf, ram_size, pos);
	free(outbuf);
	if (done < ram_size) {
		fprintf(stderr, "Short write: %d\n", errno);
		return -1;
	}

	return 0;
}

static int copy_file(struct btrfs_root *root, int fd, struct btrfs_key *key)
{
	struct extent_buffer *leaf;
	struct btrfs_path *path;
	struct btrfs_file_extent_item *fi;
	struct btrfs_key found_key;
	int ret;
	int extent_type;
	int compression;

	path = btrfs_alloc_path();
	if (!path) {
		fprintf(stderr, "Ran out of memory\n");
		return -1;
	}
	path->skip_locking = 1;

	key->offset = 0;
	key->type = BTRFS_EXTENT_DATA_KEY;

	ret = btrfs_search_slot(NULL, root, key, path, 0, 0);
	if (ret < 0) {
		fprintf(stderr, "Error searching %d\n", ret);
		btrfs_free_path(path);
		return ret;
	}

	leaf = path->nodes[0];
	while (1) {
		if (path->slots[0] >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0) {
				fprintf(stderr, "Error searching %d\n", ret);
				btrfs_free_path(path);
				return ret;
			} else if (ret) {
				/* No more leaves to search */
				break;
			}
			leaf = path->nodes[0];
			continue;
		}
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);
		if (found_key.objectid != key->objectid)
			break;
		if (found_key.type != key->type)
			break;
		fi = btrfs_item_ptr(leaf, path->slots[0],
				    struct btrfs_file_extent_item);
		extent_type = btrfs_file_extent_type(leaf, fi);
		compression = btrfs_file_extent_compression(leaf, fi);
		if (compression >= BTRFS_COMPRESS_LAST) {
			fprintf(stderr, "Don't support compression yet %d\n",
				compression);
			btrfs_free_path(path);
			return -1;
		}

		if (extent_type == BTRFS_FILE_EXTENT_PREALLOC)
			continue;
		if (extent_type == BTRFS_FILE_EXTENT_INLINE) {
			ret = copy_one_inline(fd, path, found_key.offset);
			if (ret) {
				btrfs_free_path(path);
				return -1;
			}
		} else if (extent_type == BTRFS_FILE_EXTENT_REG) {
			ret = copy_one_extent(root, fd, leaf, fi,
					      found_key.offset);
			if (ret) {
				btrfs_free_path(path);
				return ret;
			}
		} else {
			printf("Weird extent type %d\n", extent_type);
		}
		path->slots[0]++;
	}

	btrfs_free_path(path);
	return 0;
}

static int search_dir(struct btrfs_root *root, struct btrfs_key *key,
		      const char *dir)
{
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_dir_item *dir_item;
	struct btrfs_key found_key, location;
	char filename[BTRFS_NAME_LEN + 1];
	unsigned long name_ptr;
	int name_len;
	int ret;
	int fd;
	u8 type;

	path = btrfs_alloc_path();
	if (!path) {
		fprintf(stderr, "Ran out of memory\n");
		return -1;
	}
	path->skip_locking = 1;

	key->offset = 0;
	key->type = BTRFS_DIR_INDEX_KEY;

	ret = btrfs_search_slot(NULL, root, key, path, 0, 0);
	if (ret < 0) {
		fprintf(stderr, "Error searching %d\n", ret);
		btrfs_free_path(path);
		return ret;
	}

	leaf = path->nodes[0];
	while (1) {
		if (path->slots[0] >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0) {
				fprintf(stderr, "Error searching %d\n", ret);
				btrfs_free_path(path);
				return ret;
			} else if (ret) {
				/* No more leaves to search */
				break;
			}
			leaf = path->nodes[0];
			continue;
		}
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);
		if (found_key.objectid != key->objectid)
			break;
		if (found_key.type != key->type)
			break;
		dir_item = btrfs_item_ptr(leaf, path->slots[0],
					  struct btrfs_dir_item);
		name_ptr = (unsigned long)(dir_item + 1);
		name_len = btrfs_dir_name_len(leaf, dir_item);
		read_extent_buffer(leaf, filename, name_ptr, name_len);
		filename[name_len] = '\0';
		type = btrfs_dir_type(leaf, dir_item);
		btrfs_dir_item_key_to_cpu(leaf, dir_item, &location);

		snprintf(path_name, 4096, "%s/%s", dir, filename);

		/*
		 * At this point we're only going to restore directories and
		 * files, no symlinks or anything else.
		 */
		if (type == BTRFS_FT_REG_FILE) {
			fd = open(path_name, O_CREAT|O_WRONLY, 0644);
			if (fd < 0) {
				fprintf(stderr, "Error creating %s: %d\n",
					path_name, errno);
				btrfs_free_path(path);
				return -1;
			}
			ret = copy_file(root, fd, &location);
			close(fd);
			if (ret) {
				btrfs_free_path(path);
				return ret;
			}
		} else if (type == BTRFS_FT_DIR) {
			struct btrfs_root *search_root = root;
			char *dir = strdup(path_name);

			if (!dir) {
				fprintf(stderr, "Ran out of memory\n");
				btrfs_free_path(path);
				return -1;
			}

			if (location.type == BTRFS_ROOT_ITEM_KEY) {
				search_root = btrfs_read_fs_root(root->fs_info,
								 &location);
				if (IS_ERR(search_root)) {
					free(dir);
					fprintf(stderr, "Error reading "
						"subvolume %s: %lu\n",
						path_name,
						PTR_ERR(search_root));
					return PTR_ERR(search_root);
				}

				/*
				 * A subvolume will have a key.offset of 0, a
				 * snapshot will have key.offset of a transid.
				 */
				if (search_root->root_key.offset != 0 &&
				    get_snaps == 0) {
					free(dir);
					path->slots[0]++;
					printf("Skipping snapshot %s\n",
					       filename);
					continue;
				}
			}

			if (mkdir(path_name, 0644)) {
				free(dir);
				fprintf(stderr, "Error mkdiring %s: %d\n",
					path_name, errno);
				btrfs_free_path(path);
				return -1;
			}
			ret = search_dir(search_root, &location, dir);
			free(dir);
			if (ret) {
				btrfs_free_path(path);
				return ret;
			}
		}

		path->slots[0]++;
	}

	btrfs_free_path(path);
	return 0;
}

static void usage()
{
	fprintf(stderr, "Usage: restore [-s] <device> <directory>\n");
}

int main(int argc, char **argv)
{
	struct btrfs_root *root;
	struct btrfs_key key;
	char dir_name[128];
	int len;
	int ret;
	int opt;

	while ((opt = getopt(argc, argv, "s")) != -1) {
		switch (opt) {
			case 's':
				get_snaps = 1;
				break;
			default:
				usage();
				exit(1);
		}
	}

	if (optind + 1 >= argc) {
		usage();
		exit(1);
	}

	if ((ret = check_mounted(argv[optind])) < 0) {
		fprintf(stderr, "Could not check mount status: %s\n",
			strerror(ret));
		return ret;
	} else if (ret) {
		fprintf(stderr, "%s is currently mounted.  Aborting.\n", argv[1]);
		return -EBUSY;
	}

	root = open_ctree(argv[optind], 0, 0);
	if (root == NULL) {
		fprintf(stderr, "Could not open root\n");
		return 1;
	}

	memset(path_name, 0, 4096);

	strncpy(dir_name, argv[optind + 1], 128);

	/* Strip the trailing / on the dir name */
	while (1) {
		len = strlen(dir_name);
		if (dir_name[len - 1] != '/')
			break;
		dir_name[len - 1] = '\0';
	}

	key.objectid = BTRFS_FIRST_FREE_OBJECTID;

	ret = search_dir(root->fs_info->fs_root, &key, dir_name);

	close_ctree(root);
	return ret;
}
