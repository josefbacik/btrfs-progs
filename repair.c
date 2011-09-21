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
#include "kerncompat.h"
#include "ctree.h"
#include "disk-io.h"
#include "print-tree.h"
#include "transaction.h"
#include "list.h"
#include "version.h"
#include "utils.h"

static struct btrfs_trans_handle *trans = NULL;
static int dry_run = 0;

static void print_item(struct extent_buffer *b, struct btrfs_item *item,
		       int slot)
{
	struct btrfs_disk_key disk_key;

	btrfs_item_key(b, &disk_key, slot);
	printf("bytenr %Lu item %d ", btrfs_header_bytenr(b), slot);
	btrfs_print_key(&disk_key);
	printf(" itemoff %d itemsize %d\n", btrfs_item_offset(b, item),
	       btrfs_item_size(b, item));
}

static inline int should_cow_block(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root,
				   struct extent_buffer *buf)
{
	if (btrfs_header_generation(buf) == trans->transid &&
	    !btrfs_header_flag(buf, BTRFS_HEADER_FLAG_WRITTEN) &&
	    !(root->root_key.objectid != BTRFS_TREE_RELOC_OBJECTID &&
	      btrfs_header_flag(buf, BTRFS_HEADER_FLAG_RELOC)))
		return 0;
	return 1;
}

static int cow_path(struct btrfs_root *root, struct btrfs_path *path)
{
	struct extent_buffer *tmp;
	int num_cowed = 0;
	int ret;
	int i;

	if (dry_run)
		return 0;

	if (!trans) {
		trans = btrfs_start_transaction(root, 1);
		if (IS_ERR(trans)) {
			fprintf(stderr, "Could not start transaction: %s\n",
				strerror(PTR_ERR(trans)));
			return PTR_ERR(trans);
		}
		printf("Started transid %Lu\n", trans->transid);
	}

	for (i = BTRFS_MAX_LEVEL - 1; i >= 0; i--) {

		if (!path->nodes[i])
			continue;
		if (!should_cow_block(trans, root, path->nodes[i]))
			continue;


		ret = btrfs_cow_block(trans, root, path->nodes[i],
				      path->nodes[i + 1], path->slots[i + 1],
				      &tmp);
		if (ret) {
			fprintf(stderr, "Error cow'ing block, bailing %d\n", ret);
			return -1;
		}

		path->nodes[i] = tmp;
		num_cowed++;
	}

	return num_cowed;
}

static void switch_keys(struct extent_buffer *b, unsigned long offset,
			unsigned long size, int slot)
{
	struct btrfs_key_ptr ptr;

	read_extent_buffer(b, &ptr, offset + size * slot,
			   size);
	memcpy_extent_buffer(b, offset + size * slot,
			     offset + size * (slot + 1),
			     size);
	write_extent_buffer(b, &ptr, offset + size * (slot + 1),
			    size);
	if (!dry_run)
		btrfs_mark_buffer_dirty(b);
}

static void fixup_low_keys(struct btrfs_path *path, struct extent_buffer *b,
			   struct btrfs_disk_key *key)
{
	struct extent_buffer *t;
	int level = btrfs_header_level(b) + 1;
	int i;

	for (i = level; i < BTRFS_MAX_LEVEL; i++) {
		int tslot = path->slots[i];
		if (!path->nodes[i])
			break;
		t = path->nodes[i];
		btrfs_set_node_key(t, key, tslot);
		if (!dry_run)
			btrfs_mark_buffer_dirty(path->nodes[i]);
		if (tslot != 0)
			break;
	}
}

static int delete_key(struct btrfs_path *path, unsigned long offset,
		      unsigned long size, int level, int slot)
{
	struct extent_buffer *b = path->nodes[level];
	unsigned long nritems = btrfs_header_nritems(b);

	if (nritems == 1) {
		fprintf(stderr, "Only one item left, we should be deleting "
			"this node\n");
		return -1;
	}

	memmove_extent_buffer(b, offset + size * slot,
			      offset + size * (slot + 1),
			      size * (nritems - slot - 1));
	btrfs_set_header_nritems(b, nritems - 1);
	if (!dry_run)
		btrfs_mark_buffer_dirty(b);
	if (slot == 0) {
		struct btrfs_disk_key new_key;

		read_extent_buffer(b, &new_key, offset,
				   sizeof(struct btrfs_disk_key));
		fixup_low_keys(path, b, &new_key);
	}

	return 0;
}

static int delete_key_leaf(struct btrfs_path *path)
{
	return delete_key(path, offsetof(struct btrfs_leaf, items),
			  sizeof(struct btrfs_item), 0, path->slots[0]);
}

static int check_key_order(struct btrfs_root *root, struct btrfs_path *path,
			   unsigned long offset, unsigned long size, int fix,
			   int level)
{
	struct extent_buffer *b = path->nodes[level];
	struct btrfs_disk_key first, second;
	struct btrfs_key k1, k2;
	int slot = path->slots[level];
	int did_cow = 0;
	int ret = 0;

	read_extent_buffer(b, &first, offset + size * slot,
			   sizeof(struct btrfs_disk_key));
	read_extent_buffer(b, &second, offset + size * (slot + 1),
			   sizeof(struct btrfs_disk_key));

	btrfs_disk_key_to_cpu(&k1, &first);
	btrfs_disk_key_to_cpu(&k2, &second);

	if (k1.objectid > k2.objectid) {
		fprintf(stderr, "Keys in the wrong order [objectid], swapping %d\n", slot);
		if (!fix)
			return -1;
		ret = cow_path(root, path);
		if (ret < 0)
			return ret;
		if (ret)
			did_cow = 1;
		b = path->nodes[level];

		switch_keys(b, offset, size, slot);
		if (!slot)
			fixup_low_keys(path, b, &second);
	} else if (k1.objectid < k2.objectid) {
		return did_cow;
	}

	if (k1.type > k2.type) {
		fprintf(stderr, "Keys in the wrong order [type], swapping %d\n", slot);
		if (!fix)
			return -1;
		ret = cow_path(root, path);
		if (ret < 0)
			return ret;
		if (ret)
			did_cow = 1;
		b = path->nodes[level];

		switch_keys(b, offset, size, slot);
		if (!slot)
			fixup_low_keys(path, b, &second);
	} else if (k1.type < k2.type) {
		return did_cow;
	}

	if (k1.offset > k2.offset) {
		fprintf(stderr, "Keys in wrong order [offset], swapping %d\n", slot);
		if (!fix)
			return -1;
		ret = cow_path(root, path);
		if (ret < 0)
			return ret;
		if (ret)
			did_cow = 1;
		b = path->nodes[level];

		switch_keys(b, offset, size, slot);
		if (!slot)
			fixup_low_keys(path, b, &second);
	}

	return did_cow;
}

static int check_node(struct btrfs_root *root, struct btrfs_path *path,
		      int level)
{
	struct extent_buffer *b = path->nodes[level];
	struct btrfs_key key;
	unsigned long offset = offsetof(struct btrfs_node, ptrs);
	unsigned long size = sizeof(struct btrfs_key_ptr);
	int i = 0;
	int did_cow = 0;
	int ret;
	u64 block;

	BUG_ON(level != btrfs_header_level(b));
	BUG_ON(level == 0);
again:
	for (i = 0; i < btrfs_header_nritems(b); i++) {
		btrfs_node_key_to_cpu(b, &key, i);

		path->slots[level] = i;
		/*
		 * ACTUALLY, it seems like this could happen and be completely
		 * valid, but it could also be bogus, but if it is bogus I don't
		 * feel like figuring out how to fix it.
		 *
		 *
		 * This shouldn't happen, but it could and it's tricky to fix.
		 * We can see if it's blockptr is valid and walk down to the
		 * next node and figure out what key it needs to be, but for now
		 * just exit and if anybody has this problem we'll deal with it
		 * then.
		 *
		if (key.objectid == 0) {
			fprintf(stderr, "Bad objectid value with key, exiting\n");
			return -1;
		}
		*/

		block = btrfs_node_blockptr(b, i);
		if (block == 0 ||
		    block > btrfs_super_total_bytes(&root->fs_info->super_copy)) {
			int nritems = btrfs_header_nritems(b);
			int ret;

			fprintf(stderr, "Bad node blockptr, deleting\n");
			if (dry_run)
				continue;

			ret = cow_path(root, path);
			if (ret < 0)
				return ret;
			if (ret)
				did_cow = 1;

			b = path->nodes[level];
			if (i == nritems - 1) {
				btrfs_set_header_nritems(b, nritems - 1);
				continue;
			}

			memmove_extent_buffer(b, btrfs_node_key_ptr_offset(i),
					      btrfs_node_key_ptr_offset(i + 1),
					      sizeof(struct btrfs_key_ptr) *
					      (nritems - i - 1));
			btrfs_set_header_nritems(b, nritems - 1);
			btrfs_mark_buffer_dirty(b);
			goto again;
		}

		if (i != btrfs_header_nritems(b) - 1) {
			ret = check_key_order(root, path, offset, size, 1, level);
			if (ret < 0)
				return ret;
			if (ret) {
				did_cow = 1;
				goto again;
			}
		}
	}

	return did_cow;
}

static int check_item(struct btrfs_root *root, struct extent_buffer *b,
		      struct btrfs_item *item)
{
	int ret = 0;
	u32 size, offset;

	size = btrfs_item_size(b, item);
	offset = btrfs_item_offset(b, item);
	if (size + offset > root->leafsize) {
		fprintf(stderr, "Bad item end value, attempting to fix\n");
		ret = -1;
	} else if (offset == 0) {
		fprintf(stderr, "0 offset\n");
		ret = -1;
	}

	return ret;
}

static int fix_leaf_item(struct btrfs_root *root, struct btrfs_path *path)
{
	struct btrfs_item *next, *prev;
	struct extent_buffer *b = path->nodes[0];
	struct btrfs_item *item;
	int nritems = btrfs_header_nritems(b);
	u32 offset;
	u32 size;
	u32 new_size, new_offset;
	int next_slot = path->slots[0] + 1;
	int prev_slot = path->slots[0] - 1;
	int ret;
	int did_cow = 0;

	if (path->slots[0] == nritems - 1) {
		fprintf(stderr, "Last item in the leaf, can't guess right\n");
		return -1;
	}

	did_cow = !!cow_path(root, path);
	b = path->nodes[0];
	item = btrfs_item_nr(b, path->slots[0]);

	/* Weird case, only so much we can do, hopefully we can guess right */
	if (nritems == 1) {
		offset = btrfs_item_offset(b, item);
		size = btrfs_item_size(b, item);

		if (size == 0 && offset == 0) {
			fprintf(stderr, "Couldn't fix the item, skipping\n");
			return -1;
		}

		if (size > root->leafsize && offset > root->leafsize) {
			fprintf(stderr, "Couldn't fix the item, skipping\n");
			return -1;
		}

		if (size < root->leafsize && offset > root->leafsize) {
			btrfs_set_item_offset(b, item, root->leafsize - size);
		} else if (size > root->leafsize && offset < root->leafsize) {
			btrfs_set_item_size(b, item, root->leafsize - offset);
		} else {
			fprintf(stderr, "Weird case, couldn't fix, size=%u, "
				"offset=%u\n", size, offset);
			return -1;
		}
		if (!dry_run)
			btrfs_mark_buffer_dirty(b);

		return 1;
	}

	while (1) {
		next = btrfs_item_nr(b, next_slot);
		ret = check_item(root, b, next);
		if (ret) {
			fprintf(stderr, "Neighbor is bad too, will come back"
				" and try again\n");
			return -1;
		}
		/*
		 * We can have 0 sized items, so we need to find the next real
		 * sized item.
		 */
		if (btrfs_item_size(b, next))
			break;
		next_slot++;
		if (next_slot >= nritems) {
			fprintf(stderr, "Could not find a valid neighbor %d\n",
				path->slots[0]);
			return -1;
		}
	}

	new_offset = btrfs_item_size(b, next) + btrfs_item_offset(b, next);

	if (path->slots[0] != 0) {
		while (1) {
			prev = btrfs_item_nr(b, prev_slot);
			ret = check_item(root, b, prev);
			if (ret) {
				fprintf(stderr, "Previous neighbor is bad, "
					"will come back and try again later"
					"\n");
				return -1;
			}

			if (btrfs_item_size(b, prev))
				break;
			prev_slot--;
			if (prev_slot < 0) {
				fprintf(stderr, "Could not find valid prev %d"
					"\n", path->slots[0]);
				return -1;
			}
		}

		new_size = btrfs_item_offset(b, prev) - new_offset;
	} else {
		new_size = root->leafsize - new_offset;
	}

	btrfs_set_item_offset(b, item, new_offset);
	btrfs_set_item_size(b, item, new_size);
	if (!dry_run)
		btrfs_mark_buffer_dirty(b);

	return 1;
}

static int verify_extent_item(struct btrfs_root *root, struct btrfs_path *path)
{
	struct extent_buffer *b = path->nodes[0];
	struct btrfs_extent_item *ei;
	struct btrfs_key key;
	int did_cow = 0;
	int ret;
	u64 flags;
	u64 generation;
	u64 refs;
	u64 type_flags = BTRFS_EXTENT_FLAG_DATA | BTRFS_EXTENT_FLAG_TREE_BLOCK;
	u64 valid_flags = BTRFS_EXTENT_FLAG_DATA |
		BTRFS_EXTENT_FLAG_TREE_BLOCK | BTRFS_BLOCK_FLAG_FULL_BACKREF;
	u32 size;
	u32 min_tree_size = sizeof(struct btrfs_extent_item) +
		sizeof(struct btrfs_tree_block_info) +
		sizeof(struct btrfs_extent_inline_ref);

	btrfs_item_key_to_cpu(b, &key, path->slots[0]);

	size = btrfs_item_size_nr(b, path->slots[0]);
	if (size == sizeof(struct btrfs_extent_item_v0)) {
		fprintf(stderr, "Weird, we have a v0 item in here, "
			"skipping\n");
		return 0;
	}

	/*
	if (btrfs_header_bytenr(b) == (u64)51838291968)
		btrfs_print_leaf(root, b);
	*/

	if (size < sizeof(struct btrfs_extent_item)) {
		fprintf(stderr, "Hmm, size is less than btrfs_extent_item, "
			"exiting\n");
		btrfs_print_leaf(root, b);
		return -1;
	}

	ei = btrfs_item_ptr(b, path->slots[0], struct btrfs_extent_item);
	generation = btrfs_extent_generation(b, ei);
	flags = btrfs_extent_flags(b, ei);
	refs = btrfs_extent_refs(b, ei);

	if (!refs) {
		fprintf(stderr, "No refs, bailing\n");
		btrfs_print_leaf(root, b);
		return -1;
	} else if (!generation || generation > root->fs_info->generation) {
		fprintf(stderr, "Bad generation number %Lu, deleting\n",
			generation);
		btrfs_print_leaf(root, b);
		return -1;
	} else if (!flags || flags & ~(valid_flags) ||
		   (flags & type_flags) == type_flags) {
		fprintf(stderr, "Invalid flags %Lu, determining type\n", flags);
		if (refs > 0) {
			fprintf(stderr, "Multiple refs, hard to determine type"
				", bailing\n");
			btrfs_print_leaf(root, b);
			return -1;
		}

		did_cow = cow_path(root, path);
		if (did_cow < 0)
			return did_cow;
		b = path->nodes[0];
		ei = btrfs_item_ptr(b, path->slots[0],
				    struct btrfs_extent_item);

		if (size < min_tree_size) {
			fprintf(stderr, "Looks to be a tree backref, fixing\n");
			if (dry_run)
				return 0;
			btrfs_set_extent_flags(b, ei, BTRFS_EXTENT_FLAG_TREE_BLOCK);
		} else {
			fprintf(stderr, "Looks to be a data backref, fixing\n");
			if (dry_run)
				return 0;
			btrfs_set_extent_flags(b, ei, BTRFS_EXTENT_FLAG_DATA);
		}
		btrfs_mark_buffer_dirty(b);
	}

	return did_cow;
}

static int check_key(struct btrfs_root *root, struct btrfs_path *path)
{
	struct btrfs_fs_info *info = root->fs_info;
	struct btrfs_key key;
	int ret;

	btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);

	if (key.type > 228 && key.type != BTRFS_STRING_ITEM_KEY) {
		fprintf(stderr, "Invalid key type, deleting key %u\n", key.type);
		ret = delete_key_leaf(path);
		return ret ? ret : 1;
	}

	if (key.type == 0 && key.objectid != BTRFS_FREE_SPACE_OBJECTID &&
	    key.objectid != BTRFS_FREE_INO_OBJECTID) {
		fprintf(stderr, "Invalid key type, deleting key (%Lu %u %Lu)"
			"\n", key.objectid, key.type, key.offset);
		ret = delete_key_leaf(path);
		return ret ? ret : 1;
	}

	switch (key.type) {
		case BTRFS_EXTENT_ITEM_KEY:
			if (key.offset == 0 ||
			    key.offset >
			    btrfs_super_total_bytes(&info->super_copy)) {
				fprintf(stderr, "Bad key offset, deleting %Lu\n",
					key.offset);
				ret = delete_key_leaf(path);
				return ret ? ret : 1;
			}
			break;
		default:
			break;
	}

	return 0;
}

static int verify_leaf(struct btrfs_root *root, struct btrfs_path *path)
{
	struct extent_buffer *b = path->nodes[0];
	struct btrfs_key key;

	btrfs_item_key_to_cpu(b, &key, path->slots[0]);

	switch (key.type) {
		case BTRFS_EXTENT_ITEM_KEY:
			return verify_extent_item(root, path);
		default:
			break;
	}

	return 0;
}

static int check_leaf(struct btrfs_root *root, struct btrfs_path *path)
{
	struct extent_buffer *b = path->nodes[0];
	struct btrfs_item *item;
	struct extent_buffer *new_leaf = NULL;
	u32 leaf_offset = BTRFS_LEAF_DATA_SIZE(root);
	unsigned long header = sizeof(struct btrfs_header);
	int i = 0;
	int ret;
	int retry = 0, old_retry = 0;
	int print_leaf = 0;

	/*
	 * First we want to check the size+offset values to make sure everything
	 * is the way it's supposed to be.
	 */
again:
	for (i = 0; i < btrfs_header_nritems(b); i++) {
		path->slots[0] = i;

		ret = check_key(root, path);
		if (ret < 0)
			return ret;
		if (ret) {
			print_leaf = 1;
			goto again;
		}
	}

	for (i = 0; i < btrfs_header_nritems(b); i++) {
		item = btrfs_item_nr(b, i);

		path->slots[0] = i;
		ret = check_item(root, b, item);
		if (ret) {
			ret = fix_leaf_item(root, path);
			if (dry_run)
				print_item(b, item, i);
			if (ret == 1)
				print_leaf = 1;
			retry++;
			continue;
		}
	}

	if (old_retry && retry == old_retry) {
		fprintf(stderr, "Couldn't fixup leaf\n");
		if (print_leaf) {
			printf("Fixed something, dumping leaf to make sure it "
			       "looks right\n");
			btrfs_print_leaf(root, b);
		}
		return -1;
	} else if (retry) {
		old_retry = retry;
		retry = 0;
		goto again;
	}

	for (i = 0; i < btrfs_header_nritems(b); i++) {
		u32 size, offset;

		item = btrfs_item_nr(b, i);
		size = btrfs_item_size(b, item);
		offset = btrfs_item_offset(b, item);
		if (size + offset == leaf_offset || size == 0) {
			leaf_offset -= size;
			continue;
		}

		print_leaf = 1;
		cow_path(root, path);

		if (!new_leaf) {
			fprintf(stderr, "Leaf items aren't quite in the right "
				"order, fixing\n");
			new_leaf = malloc(sizeof(struct extent_buffer) +
					  root->leafsize);
			if (!new_leaf) {
				fprintf(stderr, "Not enough memory to allocate"
					" temporary leaf\n");
				return -1;
			}
			copy_extent_buffer(new_leaf, b, 0, 0, root->leafsize);
		}
		leaf_offset -= size;
		memcpy(new_leaf->data + header + leaf_offset,
		       b->data + header + offset, size);
		btrfs_set_item_offset(new_leaf, item, leaf_offset);
	}

	if (new_leaf) {
		write_extent_buffer(b, new_leaf, 0, root->leafsize);
		if (!dry_run)
			btrfs_mark_buffer_dirty(b);
		free(new_leaf);
		new_leaf = NULL;
	}

	for (i = 0; i < btrfs_header_nritems(b); i++) {
		path->slots[0] = i;
		if (i != btrfs_header_nritems(b) - 1) {
			ret = check_key_order(root, path, offsetof(struct btrfs_leaf, items),
					      sizeof(struct btrfs_item), 0, 0);
			if (ret) {
				fprintf(stderr, "Keys are out of order in a "
					"leaf, this program cant fix that yet"
					", tell the author so he can get off "
					"his lazy ass and fix that\n");
				btrfs_print_leaf(root, b);
				return -1;
			}
		}
	}

	for (i = 0; i < btrfs_header_nritems(b); i++) {
		item = btrfs_item_nr(b, i);

		ret = verify_leaf(root, path);
		if (ret)
			return ret;
	}

	if (print_leaf) {
		printf("Fixed something, dumping leaf to make sure it "
		       "looks right\n");
		btrfs_print_leaf(root, b);
	}

	return 0;
}

static int check_children(struct btrfs_root *root, struct btrfs_path *path,
			  int level)
{
	struct extent_buffer *b = path->nodes[level];
	int i = 0;
	int ret;

	for (i = 0; i < btrfs_header_nritems(b); i++) {
		struct extent_buffer *tmp;

		path->slots[level] = i;
		tmp = read_tree_block(root, btrfs_node_blockptr(b, i),
				      btrfs_level_size(root, level - 1),
				      btrfs_node_ptr_generation(b, i));
		if (!tmp) {
			fprintf(stderr, "Failed to read blocknr %Lu\n",
				btrfs_node_blockptr(b, i));
			continue;
		}
		path->nodes[level - 1] = tmp;
		if (btrfs_header_level(tmp)) {
			ret = check_node(root, path, level - 1);
			if (ret) {
				free_extent_buffer(tmp);
				return ret;
			}
			ret = check_children(root, path, level - 1);
			if (ret) {
				free_extent_buffer(tmp);
				return ret;
			}
		} else {
			ret = check_leaf(root, path);
			if (ret) {
				free_extent_buffer(tmp);
				return ret;
			}
		}
		free_extent_buffer(tmp);
	}

	return 0;
}

static int check_ref(struct btrfs_root *root, u64 bytenr, u64 size)
{
	struct btrfs_root *extent_root = root->fs_info->extent_root;
	struct btrfs_key key;
	struct btrfs_path *tmp;
	int ret;

	tmp = btrfs_alloc_path();
	if (!tmp) {
		fprintf(stderr, "Failed to alloc path\n");
		return -1;
	}

	key.objectid = bytenr;
	key.type = BTRFS_EXTENT_ITEM_KEY;
	key.offset = size;

	ret = btrfs_search_slot(NULL, extent_root, &key, tmp, 0, 0);
	btrfs_free_path(tmp);
	if (ret < 0) {
		fprintf(stderr, "Failed to do search %d\n", ret);
		return -1;
	} else if (!ret) {
		return 0;
	}

	fprintf(stderr, "Couldn't find an extent ref for bytenr %llu\n", key.objectid);
	return 0;
}

static int check_leaf_refs(struct btrfs_root *root, struct btrfs_path *path)
{
	struct btrfs_file_extent_item *item;
	struct extent_buffer *b = path->nodes[0];
	struct btrfs_key key;
	int i;
	int ret;

	for (i = 0; i < btrfs_header_level(b); i++) {
		path->slots[0] = i;

		btrfs_node_key_to_cpu(b, &key, i);
		if (key.type != BTRFS_EXTENT_DATA_KEY)
			continue;

		item = btrfs_item_ptr(b, i, struct btrfs_file_extent_item);
		if (btrfs_file_extent_type(b, item) ==
		    BTRFS_FILE_EXTENT_INLINE)
			continue;
		ret = check_ref(root, btrfs_file_extent_disk_bytenr(b, item),
				btrfs_file_extent_disk_num_bytes(b, item));
		if (ret)
			return ret;
	}

	return 0;
}

static int check_refs(struct btrfs_root *root, struct btrfs_path *path,
		      struct extent_buffer *b)
{
	int level = btrfs_header_level(b);
	int ret;
	int i = 0;

	path->nodes[level] = b;
	for (i = 0; i < btrfs_header_nritems(b); i++) {
		struct extent_buffer *tmp;

		path->slots[level] = i;
		tmp = read_tree_block(root, btrfs_node_blockptr(b, i),
				      btrfs_level_size(root, level - 1),
				      btrfs_node_ptr_generation(b, i));
		if (!tmp) {
			fprintf(stderr, "Failed to read blocknr %Lu\n",
				btrfs_node_blockptr(b, i));
			continue;
		}
		check_ref(root, btrfs_header_bytenr(tmp),
			  btrfs_level_size(root, btrfs_header_level(tmp)));
		if (btrfs_header_level(tmp)) {
			ret = check_refs(root, path, tmp);
			if (ret) {
				free_extent_buffer(tmp);
				return ret;
			}
		} else {
			path->nodes[0] = tmp;
			ret = check_leaf_refs(root, path);
			if (ret) {
				free_extent_buffer(tmp);
				return ret;
			}
		}
		free_extent_buffer(tmp);
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct extent_buffer *b;
	struct btrfs_root *root;
	struct btrfs_root *extent_root;
	struct btrfs_path *path;
	struct rb_root *tree_root;
	struct rb_node *n;
	struct btrfs_key key;
	int opt;
	int ret = 0;
	int level;

	while ((opt = getopt(argc, argv, "d")) != -1) {
		switch (opt) {
			case 'd':
				dry_run = 1;
				break;
			default:
				fprintf(stderr, "Usage: repair [-d] device\n");
				exit(1);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Usage: repair [-d] device\n");
		exit(1);
	}

	if ((ret = check_mounted(argv[optind])) < 0) {
		fprintf(stderr, "Could not check mount status: %s\n", strerror(ret));
		return ret;
	} else if (ret) {
		fprintf(stderr, "%s is currently mounted. Aborting.\n", argv[optind]);
		return -EBUSY;
	}

	root = open_ctree(argv[optind], 0, 1);
	if (root == NULL) {
		fprintf(stderr, "Could not open root\n");
		return 1;
	}

	tree_root = &root->fs_info->fs_root_cache.root;

	extent_root = root->fs_info->extent_root;

	path = btrfs_alloc_path();
	if (!path) {
		fprintf(stderr, "Could not allocate path\n");
		ret = 1;
		goto out;
	}

	b = extent_root->node;
	if (!b) {
		fprintf(stderr, "No root node?\n");
		ret = -ENOENT;
		goto out_trans;
	}

	level = btrfs_header_level(extent_root->node);
	path->nodes[level] = extent_root->node;
	if (level)
		ret = check_node(extent_root, path, level);
	else
		ret = check_leaf(extent_root, path);

	printf("Checking extent root\n");
	while (level) {
		path->nodes[level] = extent_root->node;
		ret = check_children(extent_root, path, level);
		memset(path, 0, sizeof(struct btrfs_path));
		if (ret < 0)
			goto out_trans;
		if (!ret)
			break;
	}

	btrfs_release_path(root, path);
	key.objectid = 0;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;

	printf("Finding fs roots\n");
	while (1) {
		struct btrfs_root *tmp;
		struct btrfs_key found_key;
		int done = 0;

		ret = btrfs_search_slot(NULL, root->fs_info->tree_root, &key,
					path, 0, 0);
		if (ret < 0) {
			fprintf(stderr, "Error searching tree root %d\n", ret);
			goto out_trans;
		}

		while (1) {
			if (path->slots[0] >=
			    btrfs_header_nritems(path->nodes[0])) {
				done = 1;
				break;
			}
			btrfs_item_key_to_cpu(path->nodes[0], &found_key,
					      path->slots[0]);
			if (found_key.type == BTRFS_ROOT_ITEM_KEY)
				break;
			path->slots[0]++;
		}
		btrfs_release_path(root, path);
		if (done)
			break;
		found_key.offset = (u64)-1;
		tmp = btrfs_read_fs_root(root->fs_info, &found_key);
		if (IS_ERR(tmp)) {
			ret = PTR_ERR(tmp);
			fprintf(stderr, "Error reading root %d\n", ret);
			goto out_trans;
		}
		memcpy(&key, &found_key, sizeof(struct btrfs_key));
		key.objectid++;
		key.offset = (u64)-1;
	}

	printf("Checking fs roots\n");
	for (n = rb_first(tree_root); n; n = rb_next(n)) {
		struct btrfs_root *tmp;
		struct cache_extent *cache;

		cache = rb_entry(n, struct cache_extent, rb_node);
		tmp = container_of(cache, struct btrfs_root, cache);

		if (!tmp->ref_cows || tmp->objectid == BTRFS_DATA_RELOC_TREE_OBJECTID)
			continue;

		printf("Checking root %Lu\n", tmp->objectid);
		level = btrfs_header_level(tmp->node);
		path->nodes[level] = tmp->node;
		if (level)
			ret = check_node(tmp, path, level);
		else
			ret = check_leaf(tmp, path);
		while (level) {
			path->nodes[level] = tmp->node;
			ret = check_children(tmp, path, level);
			memset(path, 0, sizeof(struct btrfs_path));
			if (ret < 0)
				goto out_trans;
			if (!ret)
				break;
		}
		memset(path, 0, sizeof(struct btrfs_path));

		printf("Checking root %Lu refs\n", tmp->objectid);
		check_ref(tmp, btrfs_header_bytenr(tmp->node),
			  btrfs_level_size(tmp, btrfs_header_level(tmp->node)));
		if (level) {
			ret = check_refs(tmp, path, tmp->node);
			if (ret)
				goto out_trans;
		}
	}

out_trans:
	if (trans)
		btrfs_commit_transaction(trans, root);
out:
	btrfs_free_path(path);
	close_ctree(root);
	return ret;
}
