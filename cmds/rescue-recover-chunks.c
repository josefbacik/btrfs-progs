/* SPDX-License-Identifier: GPL-2.0 */

#include "kerncompat.h"
#include "cmds/rescue.h"
#include "common/rbtree-utils.h"
#include "common/repair.h"
#include "common/messages.h"
#include "kernel-shared/ctree.h"
#include "kernel-shared/disk-io.h"
#include "kernel-shared/volumes.h"
#include "kernel-shared/transaction.h"

static struct extent_io_tree seen;
static struct extent_io_tree chunks;
static LIST_HEAD(devices);
static LIST_HEAD(missing);

struct dev_info {
	u64 devid;
	struct extent_io_tree extents;
	struct list_head list;
};

struct chunk_info {
	struct btrfs_key key;
	struct btrfs_chunk *chunk;
	u64 generation;
	int num_stripes;
	struct list_head list;
};

static struct dev_info *find_devid(u64 devid)
{
	struct dev_info *info;

	list_for_each_entry(info, &devices, list) {
		if (info->devid == devid)
			return info;
	}

	return NULL;
}

static int check_stripes(struct extent_buffer *eb, struct btrfs_chunk *chunk)
{
	struct dev_info *info;
	u64 stripe_len;
	int num_stripes, i;
	int new = 0;

	num_stripes = btrfs_chunk_num_stripes(eb, chunk);
	stripe_len = btrfs_chunk_stripe_len(eb, chunk);

	for (i = 0; i < num_stripes; i++) {
		u64 bytenr, devid;

		devid = btrfs_stripe_devid_nr(eb, chunk, i);
		bytenr = btrfs_stripe_offset_nr(eb, chunk, i);

		info = find_devid(devid);
		if (!info)
			return 0;

		if (test_range_bit(&info->extents, bytenr,
				   bytenr + stripe_len - 1, EXTENT_DIRTY, 0))
			return 0;
		new = 1;
	}

	return new;
}

static int search_leaf(struct extent_buffer *eb)
{
	struct chunk_info *chunk_info;
	struct btrfs_chunk *chunk;
	struct btrfs_key key;
	u64 bytenr, len, type;
	int i, num_stripes;

	for (i = 0; i < btrfs_header_nritems(eb); i++) {
		btrfs_item_key_to_cpu(eb, &key, i);

		if (key.type != BTRFS_CHUNK_ITEM_KEY)
			continue;

		chunk = btrfs_item_ptr(eb, i, struct btrfs_chunk);
		bytenr = key.offset;
		len = btrfs_chunk_length(eb, chunk);
		num_stripes = btrfs_chunk_num_stripes(eb, chunk);

		type = btrfs_chunk_type(eb, chunk) &
			BTRFS_BLOCK_GROUP_PROFILE_MASK;

		if (test_range_bit(&chunks, bytenr, bytenr + len - 1,
				   EXTENT_DIRTY, 0))
			continue;

		if (!check_stripes(eb, chunk))
			continue;

		printf("Found missing chunk %llu-%llu type %llu\n", bytenr,
		       bytenr + len, type);
		chunk_info = malloc(sizeof(struct chunk_info));
		if (!chunk_info) {
			error("Couldn't allocate chunk_info");
			return -ENOMEM;
		}

		chunk_info->chunk = malloc(btrfs_chunk_item_size(num_stripes));
		if (!chunk_info->chunk) {
			error("Couldn't allocate chunk");
			free(chunk_info);
			return -ENOMEM;
		}

		read_extent_buffer(eb, chunk_info->chunk,
				   btrfs_item_ptr_offset(eb, i),
				   btrfs_chunk_item_size(num_stripes));
		chunk_info->num_stripes = num_stripes;
		memcpy(&chunk_info->key, &key, sizeof(struct btrfs_key));
		chunk_info->generation = btrfs_header_generation(eb);
		INIT_LIST_HEAD(&chunk_info->list);
		list_add_tail(&chunk_info->list, &missing);
	}

	return 0;
}

static int search_for_missing_chunks(struct btrfs_fs_info *fs_info)
{
	u64 chunk_offset = 0, chunk_size = 0, offset = 0;
	u32 nodesize = btrfs_super_nodesize(fs_info->super_copy);
	int ret;

	while (1) {
		ret = btrfs_next_bg_system(fs_info, &chunk_offset, &chunk_size);
		if (ret) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		for (offset = chunk_offset;
		     offset < chunk_offset + chunk_size; offset += nodesize) {
			struct extent_buffer *eb;

			if (test_range_bit(&seen, offset, offset + nodesize - 1,
					   EXTENT_DIRTY, 0))
				continue;

			eb = read_tree_block(fs_info, offset, 0);
			if (IS_ERR(eb)) {
				set_extent_dirty(&seen, offset, offset + nodesize - 1);
				continue;
			}

			if (btrfs_header_owner(eb) !=
			    BTRFS_CHUNK_TREE_OBJECTID) {
				free_extent_buffer_nocache(eb);
				continue;
			}

			if (btrfs_header_level(eb) != 0) {
				free_extent_buffer_nocache(eb);
				continue;
			}

			ret = search_leaf(eb);
			free_extent_buffer_nocache(eb);
			if (ret)
				break;
		}
	}

	return ret;
}

static struct dev_info *add_devid(u64 devid)
{
	struct dev_info *info;

	info = find_devid(devid);
	if (info)
		return info;

	info = calloc(1, sizeof(struct dev_info));
	if (!info)
		return NULL;

	info->devid = devid;
	extent_io_tree_init(&info->extents);
	list_add_tail(&info->list, &devices);
	return info;
}

static int populate_stripes(struct extent_buffer *eb,
			    struct btrfs_chunk *chunk)
{
	struct dev_info *info;
	u64 stripe_len;
	int num_stripes, i;

	num_stripes = btrfs_chunk_num_stripes(eb, chunk);
	stripe_len = btrfs_chunk_stripe_len(eb, chunk);

	for (i = 0; i < num_stripes; i++) {
		u64 bytenr, devid;

		devid = btrfs_stripe_devid_nr(eb, chunk, i);
		bytenr = btrfs_stripe_offset_nr(eb, chunk, i);

		info = add_devid(devid);
		if (!info) {
			error("couldn't allocate dev info");
			return -ENOMEM;
		}

		set_extent_dirty(&info->extents, bytenr,
				 bytenr + stripe_len -1);
	}

	return 0;
}

static bool in_range(u64 a_start, u64 a_len, u64 b_start, u64 b_len)
{
	if (a_start + a_len <= b_start)
		return false;
	if (b_start + b_len <= a_start)
		return false;
	return true;
}

static bool chunk_infos_overlap(struct chunk_info *a, struct chunk_info *b)
{
	struct btrfs_stripe *a_stripes = &a->chunk->stripe;
	struct btrfs_stripe *b_stripes = &b->chunk->stripe;
	u64 a_bytenr = a->key.offset;
	u64 b_bytenr = b->key.offset;
	u64 a_len = btrfs_stack_chunk_length(a->chunk);
	u64 b_len = btrfs_stack_chunk_length(b->chunk);
	int a_num_stripes = a->num_stripes;
	int b_num_stripes = b->num_stripes;
	int i, c;

	/* Are the chunks themselves in the same range? */
	if (in_range(a_bytenr, a_len, b_bytenr, b_len))
		return true;

	/* Are any of the stripes in the same range? */
	for (i = 0; i < a_num_stripes; i++) {
		struct btrfs_stripe *a_stripe = a_stripes + i;
		u64 a_devid = btrfs_stack_stripe_devid(a_stripe);
		u64 a_stripe_bytenr = btrfs_stack_stripe_offset(a_stripe);

		for (c = 0; c < b_num_stripes; c++) {
			struct btrfs_stripe *b_stripe = b_stripes + c;
			u64 b_devid = btrfs_stack_stripe_devid(b_stripe);
			u64 b_stripe_bytenr = btrfs_stack_stripe_offset(b_stripe);

			if (b_devid != a_devid)
				continue;

			if (in_range(a_stripe_bytenr, a_len, b_stripe_bytenr,
				     b_len))
				return true;
		}
	}

	return false;
}

/*
 * We may have multiple chunks that point to the same device extents, so we need
 * to pick the newest one.  Loop through the list, any two chunks that have
 * overlapping device extents we delete the oldest one and start again until the
 * list has no overlapping chunks.
 */
static void cull_missing_chunks(void)
{
	struct chunk_info *cur, *tmp;
	int culled = 0;
again:
	list_for_each_entry(cur, &missing, list) {
		tmp = cur;
		list_for_each_entry_continue(tmp, &missing, list) {
			if (!chunk_infos_overlap(cur, tmp))
				continue;
			if (tmp->generation > cur->generation) {
				list_del(&cur->list);
				free(cur->chunk);
				free(cur);
				culled++;
				goto again;
			}
		}
	}

	if (culled)
		printf("Culled %d overlapping chunks\n", culled);
}

static int build_chunk_cache(struct extent_buffer *eb)
{
	struct btrfs_key key;
	struct btrfs_chunk *chunk;
	u64 bytenr, len;
	int i, ret;

	set_extent_dirty(&seen, eb->start, eb->start + eb->len - 1);

	for (i = 0; i < btrfs_header_nritems(eb); i++) {
		if (btrfs_header_level(eb)) {
			struct extent_buffer *tmp;
			u64 bytenr, gen;

			bytenr = btrfs_node_blockptr(eb, i);
			gen = btrfs_node_ptr_generation(eb, i);

			tmp = read_tree_block(eb->fs_info, bytenr, gen);
			if (IS_ERR(tmp)) {
				error("Couldn't read chunk block, run btrfs rescue tree-recover");
				return PTR_ERR(tmp);
			}

			ret = build_chunk_cache(tmp);
			free_extent_buffer_nocache(tmp);
			if (ret)
				return ret;
			continue;
		}

		btrfs_item_key_to_cpu(eb, &key, i);
		if (key.type != BTRFS_CHUNK_ITEM_KEY)
			continue;

		chunk = btrfs_item_ptr(eb, i, struct btrfs_chunk);
		bytenr = key.offset;
		len = btrfs_chunk_length(eb, chunk);
		set_extent_dirty(&chunks, bytenr, bytenr + len - 1);
		ret = populate_stripes(eb, chunk);
		if (ret)
			return ret;
	}

	return 0;
}

static int restore_missing_chunks(struct btrfs_fs_info *fs_info)
{
	struct chunk_info *cur;
	struct btrfs_trans_handle *trans;
	int ret;

	trans = btrfs_start_transaction(fs_info->chunk_root, 0);
	if (IS_ERR(trans)) {
		error("Couldn't start transaction %ld", PTR_ERR(trans));
		return PTR_ERR(trans);
	}
	trans->reinit_extent_tree = 1;

	list_for_each_entry(cur, &missing, list) {
		printf("Inserting chunk %llu", cur->key.offset);
		ret = btrfs_insert_item(trans, fs_info->chunk_root,
					&cur->key, cur->chunk,
					btrfs_chunk_item_size(cur->num_stripes));
		if (ret) {
			error("Couldn't insert item");
			return ret;
		}
	}

	return btrfs_commit_transaction(trans, fs_info->chunk_root);
}

int btrfs_find_recover_chunks(const char *path)
{
	struct btrfs_fs_info *fs_info;
	struct extent_io_tree *excluded_extents;
	struct open_ctree_flags ocf = {};
	int ret = 0;

	ocf.filename = path;
	ocf.flags = OPEN_CTREE_WRITES | OPEN_CTREE_ALLOW_TRANSID_MISMATCH;

	fs_info = open_ctree_fs_info(&ocf);
	if (!fs_info) {
		error("open ctree failed, try btrfs rescue tree-recover");
		return -1;
	}

	fs_info->suppress_check_block_errors = 1;

	extent_io_tree_init(&seen);

	excluded_extents = malloc(sizeof(*excluded_extents));
	if (!excluded_extents) {
		error("Couldn't allocate excluded extents\n");
		ret = -ENOMEM;
		goto out;
	}
	extent_io_tree_init(excluded_extents);
	fs_info->excluded_extents = excluded_extents;

	printf("Walking all our trees and pinning down the currently accessible blocks\n");
	ret = btrfs_mark_used_tree_blocks(fs_info, excluded_extents);
	if (ret) {
		error("Couldn't pin down excluded extents, if there were errors run btrfs rescue tree-recover");
		goto out;
	}

	ret = build_chunk_cache(fs_info->chunk_root->node);
	if (ret)
		goto out;
	ret = search_for_missing_chunks(fs_info);
	if (ret)
		goto out;
	if (list_empty(&missing)) {
		printf("No missing chunks, we're all done\n");
		goto out;
	}
	cull_missing_chunks();
	ret = restore_missing_chunks(fs_info);
out:
	if (fs_info->excluded_extents) {
		extent_io_tree_cleanup(fs_info->excluded_extents);
		free(fs_info->excluded_extents);
	}
	extent_io_tree_cleanup(&seen);
	printf("doing close???\n");
	close_ctree_fs_info(fs_info);
	return ret;
}
