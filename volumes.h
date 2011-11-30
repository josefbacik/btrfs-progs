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

#ifndef __BTRFS_VOLUMES_
#define __BTRFS_VOLUMES_
struct btrfs_device {
	struct list_head dev_list;
	struct btrfs_root *dev_root;
	struct btrfs_fs_devices *fs_devices;

	u64 total_ios;

	int fd;

	int writeable;

	char *name;

	/* these are read off the super block, only in the progs */
	char *label;
	u64 total_devs;
	u64 super_bytes_used;

	/* the internal btrfs device id */
	u64 devid;

	/* size of the device */
	u64 total_bytes;

	/* bytes used */
	u64 bytes_used;

	/* optimal io alignment for this device */
	u32 io_align;

	/* optimal io width for this device */
	u32 io_width;

	/* minimal io size for this device */
	u32 sector_size;

	/* type and info about this device */
	u64 type;

	/* physical drive uuid (or lvm uuid) */
	u8 uuid[BTRFS_UUID_SIZE];
};

struct btrfs_fs_devices {
	u8 fsid[BTRFS_FSID_SIZE]; /* FS specific uuid */

	/* the device with this id has the most recent copy of the super */
	u64 latest_devid;
	u64 latest_trans;
	/* the device with this id has the least recent copy of the super */
	u64 earliest_devid;
	u64 earliest_trans;
	u64 lowest_devid;
	int latest_bdev;
	int earliest_bdev;
	int lowest_bdev;
	struct list_head devices;
	struct list_head list;

	int seeding;
	struct btrfs_fs_devices *seed;
};

struct btrfs_bio_stripe {
	struct btrfs_device *dev;
	u64 physical;
};

struct btrfs_multi_bio {
	int error;
	int num_stripes;
	struct btrfs_bio_stripe stripes[];
};

#define btrfs_multi_bio_size(n) (sizeof(struct btrfs_multi_bio) + \
			    (sizeof(struct btrfs_bio_stripe) * (n)))

int btrfs_alloc_dev_extent(struct btrfs_trans_handle *trans,
			   struct btrfs_device *device,
			   u64 chunk_tree, u64 chunk_objectid,
			   u64 chunk_offset,
			   u64 num_bytes, u64 *start);
int __btrfs_map_block(struct btrfs_mapping_tree *map_tree, int rw,
		      u64 logical, u64 *length, u64 *type,
		      struct btrfs_multi_bio **multi_ret, int mirror_num);
int btrfs_map_block(struct btrfs_mapping_tree *map_tree, int rw,
		    u64 logical, u64 *length,
		    struct btrfs_multi_bio **multi_ret, int mirror_num);
int btrfs_next_metadata(struct btrfs_mapping_tree *map_tree, u64 *logical,
			u64 *size);
int btrfs_rmap_block(struct btrfs_mapping_tree *map_tree,
		     u64 chunk_start, u64 physical, u64 devid,
		     u64 **logical, int *naddrs, int *stripe_len);
int btrfs_read_sys_array(struct btrfs_root *root);
int btrfs_read_chunk_tree(struct btrfs_root *root);
int btrfs_alloc_chunk(struct btrfs_trans_handle *trans,
		      struct btrfs_root *extent_root, u64 *start,
		      u64 *num_bytes, u64 type);
int btrfs_alloc_data_chunk(struct btrfs_trans_handle *trans,
			   struct btrfs_root *extent_root, u64 *start,
			   u64 num_bytes, u64 type);
int btrfs_read_super_device(struct btrfs_root *root, struct extent_buffer *buf);
int btrfs_add_device(struct btrfs_trans_handle *trans,
		     struct btrfs_root *root,
		     struct btrfs_device *device);
int btrfs_open_devices(struct btrfs_fs_devices *fs_devices,
		       int flags);
int btrfs_close_devices(struct btrfs_fs_devices *fs_devices);
int btrfs_add_device(struct btrfs_trans_handle *trans,
		     struct btrfs_root *root,
		     struct btrfs_device *device);
int btrfs_update_device(struct btrfs_trans_handle *trans,
			struct btrfs_device *device);
int btrfs_scan_one_device(int fd, const char *path,
			  struct btrfs_fs_devices **fs_devices_ret,
			  u64 *total_devs, u64 super_offset);
int btrfs_num_copies(struct btrfs_mapping_tree *map_tree, u64 logical, u64 len);
int btrfs_bootstrap_super_map(struct btrfs_mapping_tree *map_tree,
			      struct btrfs_fs_devices *fs_devices);
struct list_head *btrfs_scanned_uuids(void);
int btrfs_add_system_chunk(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root, struct btrfs_key *key,
			   struct btrfs_chunk *chunk, int item_size);
int btrfs_chunk_readonly(struct btrfs_root *root, u64 chunk_offset);
#endif
