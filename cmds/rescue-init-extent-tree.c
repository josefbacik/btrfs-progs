/* SPDX-License-Identifier: GPL-2.0 */

#include "kerncompat.h"
#include "cmds/rescue.h"
#include "common/repair.h"
#include "common/messages.h"
#include "mkfs/common.h"
#include "kernel-shared/ctree.h"
#include "kernel-shared/disk-io.h"
#include "kernel-shared/volumes.h"
#include "kernel-shared/transaction.h"


#include "kernel-shared/backref.h"

#define PROBLEM 10467695652864ULL

typedef int (root_cb_t)(struct btrfs_root *root);

static struct extent_io_tree inserted;

static void print_paths(struct btrfs_root *root, u64 inum)
{
	struct btrfs_path path;
	struct inode_fs_paths *ipath;
	int i;
	int ret;

	btrfs_init_path(&path);

	ipath = init_ipath(4096, root, &path);
	if (IS_ERR(ipath)) {
		printf("Couldn't allocate ipath\n");
		return;
	}

	ret = paths_from_inode(inum, ipath);
	printf("elem_cnt %d elem_missed %d ret %d\n", ipath->fspath->elem_cnt, ipath->fspath->elem_missed, ret);
	for (i = 0; i < ipath->fspath->elem_cnt; i++) {
		char *val = (char *)(ipath->fspath->val[i]);
		printf("%s\n", val);
	}
	btrfs_release_path(&path);
	free_ipath(ipath);
}

static int foreach_root(struct btrfs_fs_info *fs_info,
			root_cb_t cb)
{
	struct btrfs_root *root;
	struct btrfs_key key = { .type = BTRFS_ROOT_ITEM_KEY };
	struct btrfs_path path;
	int ret;

	btrfs_init_path(&path);
again:
	ret = btrfs_search_slot(NULL, fs_info->tree_root, &key, &path, 0, 0);
	if (ret < 0) {
		error("Couldn't search tree root?\n");
		return ret;
	}

	if (ret > 0) {
		if (path.slots[0] >= btrfs_header_nritems(path.nodes[0])) {
			ret = btrfs_next_item(fs_info->tree_root, &path);
			if (ret)
				goto out;
		}
	}

	do {
		struct btrfs_key found_key;

		btrfs_item_key_to_cpu(path.nodes[0], &found_key,
				      path.slots[0]);
		if (found_key.type != BTRFS_ROOT_ITEM_KEY)
			continue;

		if (found_key.objectid == BTRFS_EXTENT_TREE_OBJECTID)
			continue;

		root = btrfs_read_fs_root(fs_info, &found_key);
		if (IS_ERR(root)) {
			error("Error loading root");
			ret = PTR_ERR(root);
			break;
		}

		ret = cb(root);
		if (ret) {
			printf("wtf\n");
			break;
		}
		memcpy(&key, &root->root_key, sizeof(key));
		key.offset++;
		btrfs_release_path(&path);
		goto again;
	} while ((ret = btrfs_next_item(fs_info->tree_root, &path)) == 0);

out:
	if (ret > 0)
		ret = 0;

	if (ret)
		printf("it failed?? %d\n", ret);
	btrfs_release_path(&path);
	return ret;
}

static int process_leaf_item(struct btrfs_root *root,
			     struct extent_buffer *eb, int slot)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_file_extent_item *fi;
	struct btrfs_block_group *block_group;
	struct btrfs_path path;
	struct btrfs_key key;
	u64 bytenr;
	int ret;

	btrfs_item_key_to_cpu(eb, &key, slot);
	if (key.type != BTRFS_EXTENT_DATA_KEY)
		return 0;
	fi = btrfs_item_ptr(eb, slot, struct btrfs_file_extent_item);
	if (btrfs_file_extent_type(eb, fi) ==
	    BTRFS_FILE_EXTENT_INLINE)
		return 0;
	bytenr = btrfs_file_extent_disk_bytenr(eb, fi);
	if (bytenr == 0)
		return 0;

	block_group = btrfs_lookup_block_group(eb->fs_info, bytenr);
	if (block_group)
		return 0;

	printf("\nFound an extent we don't have a block group for in the file\n");
	print_paths(root, key.objectid);
	printf("Deleting\n");
	trans = btrfs_start_transaction(root, 1);
	if (IS_ERR(trans)) {
		error("couldn't start a trans handle %d", (int)PTR_ERR(trans));
		return PTR_ERR(trans);
	}
	trans->reinit_extent_tree = true;

	btrfs_init_path(&path);
	ret = btrfs_search_slot(trans, root, &key, &path, -1, 1);
	if (ret) {
		if (ret > 0)
			ret = -ENOENT;
		error("error searching for key?? %d", ret);
		return ret;
	}
	ret = btrfs_del_item(trans, root, &path);
	if (ret) {
		error("couldn't delete item %d", ret);
		return ret;
	}
	btrfs_release_path(&path);
	ret = btrfs_commit_transaction(trans, root);
	if (ret) {
		error("error committing transaction %d", ret);
		return ret;
	}
	return 1;
}

static int look_for_bad_extents(struct btrfs_root *root,
				struct extent_buffer *eb,
				u64 *current)
{
	int pct;
	int i, ret;

	for (i = 0; i < btrfs_header_nritems(eb); i++) {
		if (btrfs_header_level(eb) != 0) {
			struct extent_buffer *tmp;
			u64 bytenr, gen;

			bytenr = btrfs_node_blockptr(eb, i);
			gen = btrfs_node_ptr_generation(eb, i);
			tmp = read_tree_block(eb->fs_info, bytenr, gen);
			if (IS_ERR(tmp)) {
				error("couldn't read block, please run btrfs rescue tree-recover");
				return PTR_ERR(tmp);
			}
			ret = look_for_bad_extents(root, tmp, current);
			free_extent_buffer_nocache(tmp);
			if (ret)
				return ret;
			continue;
		}

		ret = process_leaf_item(root, eb, i);
		if (ret)
			return ret;
	}

	*current += root->fs_info->nodesize;
	pct = (int)((*current * 100ULL) / btrfs_root_used(&root->root_item));
	printf("\rprocessed %llu of %llu possible bytes, %d%%",
	       *current, btrfs_root_used(&root->root_item), pct);
	return 0;
}

static int clear_bad_extents(struct btrfs_root *root)
{
	int ret;

	do {
		u64 current = 0;

		printf("searching %llu for bad extents\n",
		       root->root_key.objectid);
		ret = look_for_bad_extents(root, root->node, &current);
		printf("\n");
	} while (ret == 1);

	return ret;
}

static void record_root_in_trans(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root)
{
	if (root->last_trans != trans->transid) {
		root->track_dirty = 1;
		root->last_trans = trans->transid;
		root->commit_root = root->node;
		extent_buffer_get(root->node);
	}
}

static u64 space_cache_ino(struct btrfs_fs_info *fs_info, struct btrfs_path *path,
			   u64 block_group)
{
	struct btrfs_root *root = fs_info->tree_root;
	struct btrfs_free_space_header *header;
	struct btrfs_key key = {
		.objectid = BTRFS_FREE_SPACE_OBJECTID,
		.type = 0,
		.offset = block_group,
	};
	struct btrfs_disk_key disk_key;
	int ret;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret != 0) {
		btrfs_release_path(path);
		return 0;
	}

	header = btrfs_item_ptr(path->nodes[0], path->slots[0],
				struct btrfs_free_space_header);
	btrfs_free_space_key(path->nodes[0], header, &disk_key);
	btrfs_release_path(path);
	btrfs_disk_key_to_cpu(&key, &disk_key);
	return key.objectid;
}

static int clear_space_cache(struct btrfs_trans_handle *trans, u64 block_group)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct btrfs_root *root = fs_info->tree_root;
	struct btrfs_path path;
	struct btrfs_key key;
	u64 ino;
	int start_slot, end_slot;
	int ret;

	printf("deleting space cache for %llu\n", block_group);
	btrfs_init_path(&path);
	ino = space_cache_ino(fs_info, &path, block_group);
	if (ino == 0)
		return 0;

	key.objectid = ino;
	key.type = BTRFS_INODE_ITEM_KEY;
	key.offset = 0;
again:
	ret = btrfs_search_slot(trans, root, &key, &path, -1, 1);
	if (ret < 0) {
		error("Error searching for space cache %d\n", ret);
		return ret;
	}

	ret = 0;
	if (path.slots[0] >= btrfs_header_nritems(path.nodes[0]))
		goto out;

	btrfs_item_key_to_cpu(path.nodes[0], &key, path.slots[0]);
	if (key.objectid != ino)
		goto out;

	printf("deleting [%llu %u %llu]\n", key.objectid, key.type, key.offset);
	start_slot = end_slot = path.slots[0];
	while (1) {
		end_slot++;
		if (end_slot >= btrfs_header_nritems(path.nodes[0])) {
			ret = btrfs_del_items(trans, root, &path, start_slot,
					      end_slot - start_slot);
			if (ret) {
				error("Couldn't delete space cache %d\n", ret);
				goto out;
			}
			btrfs_release_path(&path);
			goto again;
		}
		btrfs_item_key_to_cpu(path.nodes[0], &key, end_slot);
		if (key.objectid != ino)
			break;
		printf("deleting [%llu %u %llu]\n", key.objectid, key.type, key.offset);
	}

	ret = btrfs_del_items(trans, root, &path, start_slot,
			      end_slot - start_slot);
	if (ret)
		error("Couldn't delete space cache %d\n", ret);
out:
	btrfs_release_path(&path);
	return ret;
}

static int btrfs_fsck_reinit_root(struct btrfs_trans_handle *trans,
				  struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct extent_buffer *c;
	struct extent_buffer *old = root->node;
	int level;
	int ret;
	struct btrfs_disk_key disk_key = {0,0,0};

	level = 0;

	c = btrfs_alloc_free_block(trans, root, fs_info->nodesize,
				   root->root_key.objectid,
				   &disk_key, level, 0, 0);
	if (IS_ERR(c))
		return PTR_ERR(c);

	memset_extent_buffer(c, 0, 0, sizeof(struct btrfs_header));
	btrfs_set_header_level(c, level);
	btrfs_set_header_bytenr(c, c->start);
	btrfs_set_header_generation(c, trans->transid);
	btrfs_set_header_backref_rev(c, BTRFS_MIXED_BACKREF_REV);
	btrfs_set_header_owner(c, root->root_key.objectid);
	btrfs_set_header_nritems(c, 0);

	write_extent_buffer(c, fs_info->fs_devices->metadata_uuid,
			    btrfs_header_fsid(), BTRFS_FSID_SIZE);

	write_extent_buffer(c, fs_info->chunk_tree_uuid,
			    btrfs_header_chunk_tree_uuid(c),
			    BTRFS_UUID_SIZE);

	btrfs_mark_buffer_dirty(c);
	/*
	 * this case can happen in the following case:
	 *
	 * reinit reloc data root, this is because we skip pin
	 * down reloc data tree before which means we can allocate
	 * same block bytenr here.
	 */
	if (old->start == c->start) {
		btrfs_set_root_generation(&root->root_item,
					  trans->transid);
		btrfs_set_root_generation_v2(&root->root_item,
					     trans->transid);
		root->root_item.level = btrfs_header_level(root->node);
		ret = btrfs_update_root(trans, fs_info->tree_root,
					&root->root_key, &root->root_item);
		if (ret) {
			free_extent_buffer(c);
			return ret;
		}
	}
	free_extent_buffer(old);
	root->node = c;
	add_root_to_dirty_list(root);
	return 0;
}

static int reinit_global_roots(struct btrfs_trans_handle *trans, u64 objectid)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct btrfs_key key = {
		.objectid = objectid,
		.type = BTRFS_ROOT_ITEM_KEY,
		.offset = 0,
	};
	struct btrfs_path path;
	struct btrfs_root *tree_root = fs_info->tree_root;
	struct btrfs_root *root;
	int ret;

	btrfs_init_path(&path);
	while (1) {
		ret = btrfs_search_slot(NULL, tree_root, &key, &path, 0, 0);
		if (ret) {
			if (ret == 1) {
				/* We should at least find the first one. */
				if (key.offset == 0)
					ret = -ENOENT;
				else
					ret = 0;
			}
			break;
		}

		btrfs_item_key_to_cpu(path.nodes[0], &key, path.slots[0]);
		if (key.objectid != objectid)
			break;
		btrfs_release_path(&path);
		root = btrfs_read_fs_root(fs_info, &key);
		if (IS_ERR(root)) {
			error("Error reading global root [%llu %llu]",
			      key.objectid, key.offset);
			ret = PTR_ERR(root);
			break;
		}
		ret = btrfs_fsck_reinit_root(trans, root);
		if (ret)
			break;
		key.offset++;
	}
	btrfs_release_path(&path);
	return ret;
}

static int reset_block_groups(struct btrfs_trans_handle *trans)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct btrfs_block_group *cache;
	struct btrfs_path path;
	struct extent_buffer *leaf;
	struct btrfs_chunk *chunk;
	struct btrfs_key key;
	int ret;
	u64 start;

	btrfs_init_path(&path);
	key.objectid = 0;
	key.type = BTRFS_CHUNK_ITEM_KEY;
	key.offset = 0;
	ret = btrfs_search_slot(NULL, fs_info->chunk_root, &key, &path, 0, 0);
	if (ret < 0) {
		btrfs_release_path(&path);
		return ret;
	}

	/*
	 * We do this in case the block groups were screwed up and had alloc
	 * bits that aren't actually set on the chunks.  This happens with
	 * restored images every time and could happen in real life I guess.
	 */
	fs_info->avail_data_alloc_bits = 0;
	fs_info->avail_metadata_alloc_bits = 0;
	fs_info->avail_system_alloc_bits = 0;

	/* First we need to create the in-memory block groups */
	while (1) {
		if (path.slots[0] >= btrfs_header_nritems(path.nodes[0])) {
			ret = btrfs_next_leaf(fs_info->chunk_root, &path);
			if (ret < 0) {
				btrfs_release_path(&path);
				return ret;
			}
			if (ret) {
				ret = 0;
				break;
			}
		}
		leaf = path.nodes[0];
		btrfs_item_key_to_cpu(leaf, &key, path.slots[0]);
		if (key.type != BTRFS_CHUNK_ITEM_KEY) {
			path.slots[0]++;
			continue;
		}

		chunk = btrfs_item_ptr(leaf, path.slots[0], struct btrfs_chunk);
		btrfs_add_block_group(fs_info, 0,
				      btrfs_chunk_type(leaf, chunk), key.offset,
				      btrfs_chunk_length(leaf, chunk));
		set_extent_dirty(&fs_info->free_space_cache, key.offset,
				 key.offset + btrfs_chunk_length(leaf, chunk));
		path.slots[0]++;
	}
	start = 0;
	while (1) {
		cache = btrfs_lookup_first_block_group(fs_info, start);
		if (!cache)
			break;
		ret = clear_space_cache(trans, cache->start);
		if (ret) {
			error("Failed to clear the space cache\n");
			break;
		}
		cache->cached = 1;
		start = cache->start + cache->length;
	}

	btrfs_release_path(&path);
	return 0;
}

static int reinit_data_reloc_root(struct btrfs_fs_info *fs_info)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root;
	struct btrfs_key key = {
		.objectid = BTRFS_DATA_RELOC_TREE_OBJECTID,
		.type = BTRFS_ROOT_ITEM_KEY,
	};
	int ret;

	root = btrfs_read_fs_root(fs_info, &key);
	if (IS_ERR(root)) {
		error("Error reading data reloc tree %ld\n", PTR_ERR(root));
		return PTR_ERR(root);
	}

	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans)) {
		error("error starting transaction for data reloc root");
		return PTR_ERR(trans);
	}

	ret = btrfs_fsck_reinit_root(trans, root);
	if (ret)
		return ret;
	ret = btrfs_make_root_dir(trans, root, BTRFS_FIRST_FREE_OBJECTID);
	if (!ret)
		ret = btrfs_commit_transaction(trans, root);
	return ret;
}

static int reset_balance(struct btrfs_trans_handle *trans)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct btrfs_root *root = fs_info->tree_root;
	struct btrfs_path path;
	struct extent_buffer *leaf;
	struct btrfs_key key;
	int del_slot, del_nr = 0;
	int ret;
	int found = 0;

	btrfs_init_path(&path);
	key.objectid = BTRFS_BALANCE_OBJECTID;
	key.type = BTRFS_BALANCE_ITEM_KEY;
	key.offset = 0;
	ret = btrfs_search_slot(trans, root, &key, &path, -1, 1);
	if (ret) {
		if (ret > 0)
			ret = 0;
		goto out;
	}

	ret = btrfs_del_item(trans, root, &path);
	if (ret)
		goto out;
	btrfs_release_path(&path);

	key.objectid = BTRFS_TREE_RELOC_OBJECTID;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = 0;
	ret = btrfs_search_slot(trans, root, &key, &path, -1, 1);
	if (ret < 0)
		goto out;
	while (1) {
		if (path.slots[0] >= btrfs_header_nritems(path.nodes[0])) {
			if (!found)
				break;

			if (del_nr) {
				ret = btrfs_del_items(trans, root, &path,
						      del_slot, del_nr);
				del_nr = 0;
				if (ret)
					goto out;
			}
			key.offset++;
			btrfs_release_path(&path);

			found = 0;
			ret = btrfs_search_slot(trans, root, &key, &path,
						-1, 1);
			if (ret < 0)
				goto out;
			continue;
		}
		found = 1;
		leaf = path.nodes[0];
		btrfs_item_key_to_cpu(leaf, &key, path.slots[0]);
		if (key.objectid > BTRFS_TREE_RELOC_OBJECTID)
			break;
		if (key.objectid != BTRFS_TREE_RELOC_OBJECTID) {
			path.slots[0]++;
			continue;
		}
		if (!del_nr) {
			del_slot = path.slots[0];
			del_nr = 1;
		} else {
			del_nr++;
		}
		path.slots[0]++;
	}

	if (del_nr)
		ret = btrfs_del_items(trans, root, &path, del_slot, del_nr);
out:
	btrfs_release_path(&path);
	return ret;
}

static int reinit_extent_tree(struct btrfs_fs_info *fs_info)
{
	struct btrfs_trans_handle *trans;
	u64 start = 0;
	int ret;

	trans = btrfs_start_transaction(fs_info->tree_root, 0);
	if (IS_ERR(trans)) {
		error("error starting transaction");
		return PTR_ERR(trans);
	}

	trans->reinit_extent_tree = true;
	printf("Clearing the extent root and re-init'ing the block groups\n");

	/*
	 * first we need to walk all of the trees except the extent tree and pin
	 * down/exclude the bytes that are in use so we don't overwrite any
	 * existing metadata.
	 * If pinned, unpin will be done in the end of transaction.
	 * If excluded, cleanup will be done in check_chunks_and_extents_lowmem.
	 */

	/*
	 * Need to drop all the block groups since we're going to recreate all
	 * of them again.
	 */
	btrfs_free_block_groups(fs_info);
	ret = reset_block_groups(trans);
	if (ret) {
		fprintf(stderr, "error resetting the block groups\n");
		return ret;
	}

	/* Ok we can allocate now, reinit the extent root */
	ret = reinit_global_roots(trans, BTRFS_EXTENT_TREE_OBJECTID);
	if (ret) {
		fprintf(stderr, "extent root initialization failed\n");
		/*
		 * When the transaction code is updated we should end the
		 * transaction, but for now progs only knows about commit so
		 * just return an error.
		 */
		return ret;
	}

	ret = reinit_global_roots(trans, BTRFS_CSUM_TREE_OBJECTID);
	if (ret) {
		fprintf(stderr, "csum root initialization failed\n");
		return ret;
	}

	/*
	 * Now we have all the in-memory block groups setup so we can make
	 * allocations properly, and the metadata we care about is safe since we
	 * pinned all of it above.
	 */
	while (1) {
		struct btrfs_block_group_item bgi;
		struct btrfs_block_group *cache;
		struct btrfs_root *extent_root = btrfs_extent_root(fs_info, 0);
		struct btrfs_key key;

		cache = btrfs_lookup_first_block_group(fs_info, start);
		if (!cache)
			break;
		start = cache->start + cache->length;
		btrfs_set_stack_block_group_used(&bgi, cache->used);
		btrfs_set_stack_block_group_chunk_objectid(&bgi,
					BTRFS_FIRST_CHUNK_TREE_OBJECTID);
		btrfs_set_stack_block_group_flags(&bgi, cache->flags);
		key.objectid = cache->start;
		key.type = BTRFS_BLOCK_GROUP_ITEM_KEY;
		key.offset = cache->length;

		printf("inserting block group %llu\n", cache->start);
		ret = btrfs_insert_item(trans, extent_root, &key, &bgi,
					sizeof(bgi));
		if (ret) {
			error("Error adding block group %d", ret);
			return ret;
		}
	}
	btrfs_run_delayed_refs(trans, -1);

	ret = reset_balance(trans);
	if (ret) {
		error("error resetting the pending balance");
		return ret;
	}


	ret = btrfs_commit_transaction(trans, fs_info->tree_root);
	if (ret) {
		error("failed to commit the transaction");
		return ret;
	}

	ret = reinit_data_reloc_root(fs_info);
	if (ret) {
		error("failed to reinit the data reloc root");
	}

	ret = foreach_root(fs_info, clear_bad_extents);
	if (ret) {
		error("failed to clear bad extents");
		return ret;
	}

	return ret;
}

static bool in_range(u64 val, u64 start, u64 len)
{
	if (val < start)
		return false;
	if (start + len < val)
		return false;
	return true;
}

static int insert_empty_extent(struct btrfs_trans_handle *trans,
			       struct btrfs_key *key, u64 generation,
			       u64 flags)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct btrfs_root *extent_root = btrfs_extent_root(fs_info, key->objectid);
	struct btrfs_extent_item *extent_item;
	struct extent_buffer *leaf;
	struct btrfs_path path;
	u64 num_bytes;
	u32 size;
	int ret;

	if (key->objectid == PROBLEM)
		printf("doing an insert of the bytenr\n");

	if (key->type == BTRFS_METADATA_ITEM_KEY)
		num_bytes = fs_info->nodesize;
	else
		num_bytes = key->offset;

	if (in_range(PROBLEM, key->objectid, num_bytes))
		printf("doing an insert that overlaps our bytenr %llu %llu\n", key->objectid, key->offset);

	set_extent_dirty(&inserted, key->objectid, key->objectid + num_bytes - 1);

	record_root_in_trans(trans, extent_root);
	btrfs_init_path(&path);

	size = sizeof(struct btrfs_extent_item);
	ret = btrfs_insert_empty_item(trans, extent_root, &path, key, size);
	if (ret) {
		btrfs_release_path(&path);
		return ret;
	}

	leaf = path.nodes[0];
	extent_item = btrfs_item_ptr(leaf, path.slots[0],
				     struct btrfs_extent_item);
	btrfs_set_extent_refs(leaf, extent_item, 0);
	btrfs_set_extent_generation(leaf, extent_item, generation);
	btrfs_set_extent_flags(leaf, extent_item, flags);
	btrfs_mark_buffer_dirty(leaf);
	btrfs_release_path(&path);

	return 0;
}

static int process_eb(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		      struct extent_buffer *eb, u64 *current)
{
	struct btrfs_key key;
	u64 ref_root = root->root_key.objectid;
	u64 parent = 0, gen;
	u64 flags;
	u32 nodesize = root->fs_info->nodesize;
	int i = 0, level = btrfs_header_level(eb);
	int ret, pct;

	if (btrfs_header_flag(eb, BTRFS_HEADER_FLAG_RELOC) ||
	    btrfs_header_owner(eb) != ref_root) {
		ret = btrfs_set_block_flags(trans, eb->start,
					    btrfs_header_level(eb),
					    BTRFS_BLOCK_FLAG_FULL_BACKREF);
		if (ret) {
			error("Couldn't set FULL_BACKREF %d\n", ret);
			return ret;
		}
		parent = eb->start;
	}

	for (i = 0; i < btrfs_header_nritems(eb); i++) {
		if (level == 0) {
			struct btrfs_key found_key, orig;
			struct btrfs_file_extent_item *fi;

			btrfs_item_key_to_cpu(eb, &found_key, i);
			btrfs_item_key_to_cpu(eb, &orig, i);
			if (found_key.type != BTRFS_EXTENT_DATA_KEY)
				continue;

			fi = btrfs_item_ptr(eb, i, struct btrfs_file_extent_item);
			if (btrfs_file_extent_type(eb, fi) ==
			    BTRFS_FILE_EXTENT_INLINE)
				continue;
			key.objectid = btrfs_file_extent_disk_bytenr(eb, fi);
			if (key.objectid == 0)
				continue;

			/*
			 * Setup the main extent key in case we have to insert
			 * it.
			 */
			key.type = BTRFS_EXTENT_ITEM_KEY;
			key.offset = btrfs_file_extent_disk_num_bytes(eb, fi);
			gen = btrfs_file_extent_generation(eb, fi);

			/* Adjust the offset for the backref. */
			found_key.offset -= btrfs_file_extent_offset(eb, fi);

			/* New extent, insert the extent item first. */
			if (!test_range_bit(&inserted, key.objectid,
					    key.objectid + key.offset - 1,
					    EXTENT_DIRTY, 0)) {
				if (in_range(PROBLEM, key.objectid, key.offset)) {
					printf("adding a bytenr that overlaps our thing, dumping paths for [%llu, %u, %llu]\n",
					       orig.objectid, orig.type, orig.offset);
					print_paths(root, orig.objectid);
				}
				ret = insert_empty_extent(trans, &key, gen,
							  BTRFS_EXTENT_FLAG_DATA);
				if (ret) {
					error("failed to insert empty ref for data %d",
					      ret);
					return ret;
				}
			} else if (key.objectid == PROBLEM) {
				printf("WTF???? we think we already inserted this bytenr?? [%llu, %u, %llu] dumping paths %llu %llu\n",
				       orig.objectid, orig.type,
				       orig.offset, key.objectid, key.offset);
				print_paths(root, orig.objectid);
			}

			ret = btrfs_inc_extent_ref(trans, root, key.objectid,
						   key.offset, parent, ref_root,
						   found_key.objectid,
						   found_key.offset);
			if (ret) {
				error("failed to insert backref for data %d",
				      ret);
				return ret;
			}
		} else {
			struct extent_buffer *tmp;

			flags = BTRFS_EXTENT_FLAG_TREE_BLOCK;
			if (parent)
				flags |= BTRFS_BLOCK_FLAG_FULL_BACKREF;

			key.objectid = btrfs_node_blockptr(eb, i);
			gen = btrfs_node_ptr_generation(eb, i);

			/*
			 * Already processed this guy, add our reference and
			 * carry on.
			 */
			if (test_range_bit(&inserted, key.objectid,
					   key.objectid + nodesize - 1,
					   EXTENT_DIRTY, 0)) {
				ret = btrfs_inc_extent_ref(trans, root,
							   key.objectid,
							   nodesize, parent,
							   ref_root, level - 1, 0);
				if (ret) {
					error("Failed to insert extent ref %d",
					      ret);
					return ret;
				}
				continue;
			}
			if (btrfs_fs_incompat(trans->fs_info, SKINNY_METADATA)) {
				key.offset = level - 1;
				key.type = BTRFS_METADATA_ITEM_KEY;
			} else {
				key.offset = nodesize;
				key.type = BTRFS_EXTENT_ITEM_KEY;
			}
			ret = insert_empty_extent(trans, &key, gen, flags);
			if (ret) {
				/*
				 * During extent tree clearing we could have
				 * updated the blocks for things like the free
				 * space tree properly, so just don't add refs
				 * for these blocks and keep walking down the
				 * tree, else return the error.
				 */
				if (ret != -EEXIST || is_fstree(ref_root)) {
					error("failed to insert the empty ref %d", ret);
					return ret;
				}
				ret = 0;
			} else {
				ret = btrfs_inc_extent_ref(trans, root,
							   key.objectid,
							   nodesize, parent,
							   ref_root,
							   level - 1, 0);
				if (ret) {
					error("couldn't insert ref %d", ret);
					return ret;
				}
			}

			tmp = read_tree_block(trans->fs_info, key.objectid, gen);
			if (IS_ERR(tmp)) {
				error("couldn't read block, please run btrfs rescue tree-recover");
				return PTR_ERR(tmp);
			}
			ret = process_eb(trans, root, tmp, current);
			free_extent_buffer_nocache(tmp);
			if (ret)
				return ret;
		}
	}

	*current += root->fs_info->nodesize;
	pct = (int)((*current * 100ULL) / btrfs_root_used(&root->root_item));
	printf("\rprocessed %llu of %llu possible bytes, %d%%",
	       *current, btrfs_root_used(&root->root_item), pct);
	fflush(stdout);

	return 0;
}

static int record_root(struct btrfs_root *root)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_key key;
	u64 flags = BTRFS_EXTENT_FLAG_TREE_BLOCK;
	u64 parent = 0;
	u64 current = 0;
	int ret;
	bool skinny_metadata = btrfs_fs_incompat(root->fs_info, SKINNY_METADATA);

	printf("Recording extents for root %llu\n", root->root_key.objectid);
	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans)) {
		error("error starting transaction");
		return PTR_ERR(trans);
	}

	key.objectid = root->node->start;
	if (skinny_metadata) {
		key.offset = btrfs_header_level(root->node);
		key.type = BTRFS_METADATA_ITEM_KEY;
	} else {
		key.offset = root->node->len;
		key.type = BTRFS_EXTENT_ITEM_KEY;
	}

	if (btrfs_header_flag(root->node, BTRFS_HEADER_FLAG_RELOC)) {
		flags |= BTRFS_BLOCK_FLAG_FULL_BACKREF;
		parent = root->node->start;
	}

	ret = insert_empty_extent(trans, &key,
				  btrfs_header_generation(root->node), flags);
	if (ret) {
		/*
		 * During extent tree clearing we could have updated the blocks
		 * for things like the free space tree properly, so just don't
		 * add refs for these blocks and keep walking down the tree,
		 * else return the error.
		 */
		if (ret != -EEXIST || is_fstree(root->root_key.objectid)) {
			error("failed to insert the ref for the root block %d",
			      ret);
			return ret;
		}
		ret = 0;
	} else {
		ret = btrfs_inc_extent_ref(trans, root, key.objectid,
					   root->node->len, parent,
					   root->root_key.objectid,
					   btrfs_header_level(root->node), 0);
		if (ret) {
			error("couldn't insert root ref %d", ret);
			return ret;
		}
	}

	ret = process_eb(trans, root, root->node, &current);
	if (ret)
		return ret;

	printf("\r\n");
	fflush(stdout);

	ret = btrfs_commit_transaction(trans, root);
	if (ret)
		error("failed to commit transaction %d", ret);
	return ret;
}

static int fix_block_accounting(struct btrfs_fs_info *fs_info)
{
	struct btrfs_trans_handle *trans;
	int ret;

	trans = btrfs_start_transaction(fs_info->tree_root, 0);
	if (IS_ERR(trans)) {
		error("couldn't start trans handle to fix block accounting");
		return PTR_ERR(trans);
	}

	ret = btrfs_fix_block_accounting(trans);
	if (ret) {
		printf("FIX BLOCK ACCOUNTING FAILED %d\n", ret);
		return ret;
	}
	return btrfs_commit_transaction(trans, fs_info->tree_root);
}

int btrfs_init_extent_tree(const char *path)
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

	extent_io_tree_init(&inserted);

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

	ret = reinit_extent_tree(fs_info);
	if (ret)
		goto out;

	ret = record_root(fs_info->chunk_root);
	if (ret)
		goto out;
	ret = record_root(fs_info->tree_root);
	if (ret)
		goto out;
	printf("doing roots\n");
	ret = foreach_root(fs_info, record_root);
	if (ret)
		goto out;
	printf("doing block accounting\n");
	ret = fix_block_accounting(fs_info);
	if (ret)
		error("The commit failed???? %d\n", ret);
out:
	if (fs_info->excluded_extents) {
		extent_io_tree_cleanup(fs_info->excluded_extents);
		free(fs_info->excluded_extents);
	}
	extent_io_tree_cleanup(&inserted);
	printf("doing close???\n");
	close_ctree_fs_info(fs_info);
	return ret;
}
