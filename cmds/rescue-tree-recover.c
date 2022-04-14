/* SPDX-License-Identifier: GPL-2.0 */

#include "kerncompat.h"
#include "cmds/rescue.h"
#include "common/rbtree-utils.h"
#include "common/repair.h"
#include "common/messages.h"
#include "kernel-shared/ctree.h"
#include "kernel-shared/disk-io.h"
#include "kernel-shared/volumes.h"

static struct extent_io_tree seen;
static struct rb_root block_cache = RB_ROOT;

struct root_info {
	u64 objectid;
	u64 bytenr;
	u64 generation;
	u8 level;
	int bad_blocks;
	int found_blocks;
	int fixed;
	int deleted;
	int update;
};

struct block_info {
	u64 bytenr;
	u64 generation;
	u64 level;
	struct btrfs_key first_key;
	struct btrfs_key last_key;
	struct rb_node n;
};

static void reset_root_info(struct root_info *info)
{
	info->bad_blocks = 0;
	info->found_blocks = 0;
	info->fixed = 0;
	info->deleted = 0;
}

/*
 * This is a little fuzzy, but figure out who has the larger ratio of good to
 * bad blocks.  If they're the same then just base it on the actual count of bad
 * blocks.  If those are the same go with the newer generation, otherwise
 * they're both bad choices.
 */
static int compare_root_info(struct root_info *a, struct root_info *b)
{
	int a_good_ratio, b_good_ratio;

	if (a->bad_blocks)
		a_good_ratio = a->found_blocks / a->bad_blocks;
	else
		a_good_ratio = a->found_blocks;
	if (b->bad_blocks)
		b_good_ratio = b->found_blocks / b->bad_blocks;
	else
		b_good_ratio = b->found_blocks;

	if (a_good_ratio > b_good_ratio)
		return 1;
	if (a_good_ratio < b_good_ratio)
		return -1;
	if (a->found_blocks == 0)
		return -1;
	if (b->found_blocks == 0)
		return 1;
	if (a->bad_blocks < b->bad_blocks)
		return 1;
	if (b->bad_blocks < a->bad_blocks)
		return -1;
	if (a->generation > b->generation)
		return 1;
	if (b->generation > a->generation)
		return -1;
	return 0;
}

/*
 * Pull the relevant information for the objectid from the backup root at the
 * given index.  If we don't have that root recorded everything will be -1.
 */
static void get_backup_root_info(struct btrfs_fs_info *fs_info,
				 struct root_info *info, int index)
{
	struct btrfs_super_block *super = fs_info->super_copy;
	struct btrfs_root_backup *backup;
	u64 gen = (u64)-1;
	u64 bytenr = (u64)-1;
	u8 level = (u8)-1;

	backup = super->super_roots + index;
	switch (info->objectid) {
	case BTRFS_ROOT_TREE_OBJECTID:
		level = btrfs_backup_tree_root_level(backup);
		gen = btrfs_backup_tree_root_gen(backup);
		bytenr = btrfs_backup_tree_root(backup);
		break;
	case BTRFS_CHUNK_TREE_OBJECTID:
		level = btrfs_backup_chunk_root_level(backup);
		gen = btrfs_backup_chunk_root_gen(backup);
		bytenr = btrfs_backup_chunk_root(backup);
		break;
	case BTRFS_EXTENT_TREE_OBJECTID:
		level = btrfs_backup_extent_root_level(backup);
		gen = btrfs_backup_extent_root_gen(backup);
		bytenr = btrfs_backup_extent_root(backup);
		break;
	case BTRFS_DEV_TREE_OBJECTID:
		level = btrfs_backup_dev_root_level(backup);
		gen = btrfs_backup_dev_root_gen(backup);
		bytenr = btrfs_backup_dev_root(backup);
		break;
	case BTRFS_CSUM_TREE_OBJECTID:
		level = btrfs_backup_csum_root_level(backup);
		gen = btrfs_backup_csum_root_gen(backup);
		bytenr = btrfs_backup_csum_root(backup);
		break;
	case BTRFS_FS_TREE_OBJECTID:
		level = btrfs_backup_fs_root_level(backup);
		gen = btrfs_backup_fs_root_gen(backup);
		bytenr = btrfs_backup_fs_root(backup);
		break;
	default:
		break;
	}

	info->bytenr = bytenr;
	info->generation = gen;
	info->level = level;
}

/*
 * Validate the child block is what we expect by checking the header values as
 * well as keys.
 */
static bool is_good_block(struct extent_buffer *parent,
			  struct extent_buffer *eb, int parent_slot)
{
	struct btrfs_key key, first_key, next_key = {};
	u64 bytenr = btrfs_node_blockptr(parent, parent_slot);
	u64 gen = btrfs_node_ptr_generation(parent, parent_slot);
	bool fstree = is_fstree(btrfs_header_owner(parent));
	enum btrfs_tree_block_status status;

	btrfs_node_key_to_cpu(parent, &first_key, parent_slot);
	if (parent_slot < (btrfs_header_nritems(parent) - 1))
		btrfs_node_key_to_cpu(parent, &next_key, parent_slot + 1);

	if (!fstree && btrfs_header_owner(parent) != btrfs_header_owner(eb))
		return false;
	if (fstree && !is_fstree(btrfs_header_owner(eb)))
		return false;
	if (btrfs_header_level(eb) != (btrfs_header_level(parent) - 1))
		return false;
	if (btrfs_header_generation(eb) != gen)
		return false;
	if (btrfs_header_bytenr(eb) != bytenr)
		return false;
	if (btrfs_header_level(eb))
		btrfs_node_key_to_cpu(eb, &key, 0);
	else
		btrfs_item_key_to_cpu(eb, &key, 0);
	if (btrfs_comp_cpu_keys(&key, &first_key))
		return false;
	if (next_key.objectid == 0)
		return true;
	if (btrfs_header_level(eb))
		btrfs_node_key_to_cpu(eb, &key, btrfs_header_nritems(eb) - 1);
	else
		btrfs_item_key_to_cpu(eb, &key, btrfs_header_nritems(eb) - 1);
	if (btrfs_comp_cpu_keys(&key, &next_key) > 0)
		return false;

	/*
	 * We should handle bad key ordering better in this tool, but for now
	 * just chuck the whole block.
	 */
	if (btrfs_header_level(eb))
		status = btrfs_check_node(eb->fs_info, NULL, eb);
	else
		status = btrfs_check_leaf(eb->fs_info, NULL, eb);
	return status == BTRFS_TREE_BLOCK_CLEAN;
}

/*
 * Recursively walk down a tree to figure out which blocks are valid and which
 * ones are not.
 */
static void get_tree_info(struct btrfs_fs_info *fs_info,
			  struct extent_buffer *eb, struct root_info *info)
{
	int i;

	if (btrfs_header_level(eb) == 0)
		return;

	for (i = 0; i < btrfs_header_nritems(eb); i++) {
		struct extent_buffer *tmp;
		u64 bytenr;
		bool debug = false;

		bytenr = btrfs_node_blockptr(eb, i);

		if (bytenr == 364635471872ULL) {
			debug = true;
			printf("CHECKING THE BAD BLOCK\n");
		}
		tmp = read_tree_block(fs_info, bytenr, 0);
		if (IS_ERR(tmp)) {
			if (debug)
				printf("COULDN'T READ, I KNOW IT'S BAD\n");
			info->bad_blocks++;
			continue;
		}
		if (debug)
			printf("OK DOING MY THING\n");
		info->found_blocks++;
		if (!is_good_block(eb, tmp, i)) {
			if (debug)
				printf("OK I SAW IT WAS BAD\n");
			free_extent_buffer_nocache(tmp);
			info->bad_blocks++;
			continue;
		}
		if (debug)
			printf("I THINK IT'S OK????\n");
		get_tree_info(fs_info, tmp, info);
		free_extent_buffer_nocache(tmp);
	}
}

static int block_info_compare(struct block_info *ins, struct block_info *exist)
{
	int ret;

	/*
	 * We want the tree in key->level->generation order,
	 *
	 * So same keys all together, highest level first, highest generation
	 * first.
	 *
	 * We use ins first because comp_cpu_keys will return 1 if the first key
	 * is larger than the second.
	 */
	ret = btrfs_comp_cpu_keys(&ins->first_key, &exist->first_key);
	if (ret)
		return ret;

	if (ins->level > exist->level)
		return -1;
	if (ins->level < exist->level)
		return 1;
	if (ins->generation > exist->generation)
		return -1;
	if (ins->generation < exist->generation)
		return 1;
	if (ins->bytenr > exist->bytenr)
		return 1;
	if (ins->bytenr < exist->bytenr)
		return -1;
	return btrfs_comp_cpu_keys(&ins->last_key, &exist->last_key);
}

static void block_info_free(struct rb_node *n)
{
	struct block_info *info = rb_entry(n, struct block_info, n);
	free(info);
}
FREE_RB_BASED_TREE(block_cache, block_info_free);

static int block_info_compare_nodes(struct rb_node *node1, struct rb_node *node2)
{
	struct block_info *ins = rb_entry(node2, struct block_info, n);
	struct block_info *exist = rb_entry(node1, struct block_info, n);

	return block_info_compare(ins, exist);
}

static int block_info_compare_keys(struct rb_node *node, void *key)
{
	struct block_info *search = (struct block_info *)key;
	struct block_info *exist = rb_entry(node, struct block_info, n);

	return block_info_compare(search, exist);
}

static int add_block_info(struct extent_buffer *eb)
{
	struct block_info *info;

	info = calloc(1, sizeof(struct block_info));
	if (!info)
		return -1;

	info->bytenr = eb->start;
	info->generation = btrfs_header_generation(eb);
	info->level = btrfs_header_level(eb);
	if (btrfs_header_level(eb)) {
		btrfs_node_key_to_cpu(eb, &info->first_key, 0);
		btrfs_node_key_to_cpu(eb, &info->last_key, btrfs_header_nritems(eb) - 1);
	} else {
		btrfs_item_key_to_cpu(eb, &info->first_key, 0);
		btrfs_item_key_to_cpu(eb, &info->last_key, btrfs_header_nritems(eb) - 1);
	}

	return rb_insert(&block_cache, &info->n, block_info_compare_nodes);
}

/*
 * This will scan all of the blocks in the metadata looking for blocks that we
 * can read with the given objectid, and we will populate the block info cache
 * with these blocks.  We also mark them as seen so we don't re-read them later
 * looking for other roots.
 */
static int populate_block_info_cache(struct btrfs_fs_info *fs_info,
				     u64 objectid)
{
	u64 chunk_offset = 0, chunk_size = 0, offset = 0;
	u32 nodesize = btrfs_super_nodesize(fs_info->super_copy);
	int ret;
	bool fstree = is_fstree(objectid);

	/*
	 * Sometimes we have to populate the block cache to find a root, so if
	 * we're not empty we can skip this step as we've already done it for
	 * this objectid.
	 */
	if (!RB_EMPTY_ROOT(&block_cache))
		return 0;

	while (1) {
		if (objectid != BTRFS_CHUNK_TREE_OBJECTID)
			ret = btrfs_next_bg_metadata(fs_info, &chunk_offset,
						     &chunk_size);
		else
			ret = btrfs_next_bg_system(fs_info, &chunk_offset,
						   &chunk_size);
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

			if (!fstree && btrfs_header_owner(eb) != objectid) {
				free_extent_buffer_nocache(eb);
				continue;
			}

			if (fstree && !is_fstree(btrfs_header_owner(eb))) {
				free_extent_buffer_nocache(eb);
				continue;
			}

			if (objectid == 10)
				printf("found a block at %llu level %u\n",
				       eb->start, btrfs_header_level(eb));
			ret = add_block_info(eb);
			if (ret) {
				fprintf(stderr, "Failed to allocate block info, bailing\n");
				break;
			}

			/*
			 * fs tree's can point at blocks they down own
			 * themselves, so don't mark fs tree blocks as seen.
			 */
			if (fstree)
				set_extent_dirty(&seen, offset,
						 offset + nodesize - 1);
			free_extent_buffer_nocache(eb);
		}
	}

	return ret;
}

/*
 * info is the block_info we're going to use, tmp is the one we're testing.  If
 * tmp falls in the same level and key space as the one we're going to use we
 * need to remove it from the tree.
 */
static bool can_free_block_info(struct block_info *tmp, struct block_info *info)
{
	/* Not the same level, bail. */
	if (tmp->level != info->level)
		return false;

	/* Last key is before our first key, bail. */
	if (btrfs_comp_cpu_keys(&tmp->last_key, &info->first_key) < 0)
		return false;

	/* First key is after our last key, bail. */
	if (btrfs_comp_cpu_keys(&tmp->first_key, &info->last_key) > 0)
		return false;
	return true;
}

/*
 * Search through the block_cache and find a block that best matches what we
 * expect from the blockptr at the given slot.
 */
static struct block_info *find_best_block(struct btrfs_fs_info *fs_info,
					  struct block_info *search,
					  struct btrfs_key *prev_last)
{
	struct block_info *info;
	struct rb_node *n, *next;

	/*
	 * Do some sanity checking on our search parameters, they came from the
	 * disk and thus could be wonky and fail to find us anything.  Reset the
	 * values to something normal based on what we've found so we have a
	 * prayer of updating stuff.
	 */
	if (search->generation > fs_info->generation)
		search->generation = fs_info->generation;

	/*
	 * We'll have the highest level first, so reset our search level to that
	 * level if ours is higher.
	 */
	n = rb_first(&block_cache);
	if (n) {
		info = rb_entry(n, struct block_info, n);
		if (search->level > info->level)
			search->level = info->level;
	}

	n = rb_search(&block_cache, search, block_info_compare_keys, &next);
	if (!n)
		n = next;
	if (!n)
		return NULL;
	info = rb_entry(n, struct block_info, n);

	/*
	 * Since we're searching primarily on key we could end up on a higher
	 * level node than we want, so search forward until we find the level we
	 * want.
	 */
	while (info->level > search->level) {
		n = rb_next(n);
		if (!n)
			return NULL;
		info = rb_entry(n, struct block_info, n);
	}

	/* We didn't find the level we wanted, bail. */
	if (info->level != search->level)
		return NULL;

	/*
	 * We can't link to a generation that is newer than us, so cycle through
	 * those as well.
	 */
	while (info->generation > search->generation) {
		n = rb_next(n);
		if (!n)
			return NULL;
		info = rb_entry(n, struct block_info, n);
	}

	if (info->level != search->level)
		return NULL;

	/*
	 * We can fudge the first block key a little bit, but if the last one is
	 * >= our next key then we can't really deal with that.
	 */
	while (search->last_key.objectid != 0 &&
	       btrfs_comp_cpu_keys(&info->last_key, &search->last_key) >= 0) {
		n = rb_next(n);
		if (!n)
			return NULL;
		info = rb_entry(n, struct block_info, n);
	}

	if (info->level != search->level)
		return NULL;

	/*
	 * If our first key doesn't match our expected first_key we may be ok,
	 * but if it's <= our prev_last we can't use this block and have to walk
	 * forward.
	 */
	while (prev_last && prev_last->objectid != 0 &&
	       btrfs_comp_cpu_keys(&info->first_key, prev_last) <= 0) {
		n = rb_next(n);
		if (!n)
			return NULL;
		info = rb_entry(n, struct block_info, n);
	}

	if (info->level != search->level)
		return NULL;

	/*
	 * Now we know that our first key and our last key land in the correct
	 * key space, our level is correct, and our owner is correct, we can
	 * remove this block_info, and we need to remove any other block_info
	 * that is even remotely related to this block so that we don't link in
	 * another block with this key space elsewhere in this tree.
	 */
	while ((n = rb_prev(&info->n)) != NULL) {
		struct block_info *tmp = rb_entry(n, struct block_info, n);

		if (!can_free_block_info(tmp, info))
			break;
		/*
		 * Ok this is the same level and exists in our key space, remove
		 * it.
		 */
		rb_erase(n, &block_cache);
		free(tmp);
	}

	/* Now search forward. */
	while ((n = rb_next(&info->n)) != NULL) {
		struct block_info *tmp = rb_entry(n, struct block_info, n);

		if (!can_free_block_info(tmp, info))
			break;
		/*
		 * Ok this is the same level and exists in our key space, remove
		 * it.
		 */
		rb_erase(n, &block_cache);
		free(tmp);
	}

	/* We can erase this block_info from the block_cache and return it. */
	rb_erase(&info->n, &block_cache);
	return info;
}

/*
 * We'll use the bytenr/level/generation in root_info to figure out how many
 * blocks we can read (they pass check_block and have matching csums), and how
 * many blocks are bad for whatever reason.
 */
static void get_root_info(struct btrfs_fs_info *fs_info,
			  struct root_info *info)
{
	struct extent_buffer *eb;

	eb = read_tree_block(fs_info, info->bytenr, 0);
	if (IS_ERR(eb)) {
		info->bad_blocks++;
		return;
	}

	/*
	 * If the bytenr doesn't match, or the owner doesn't match don't even
	 * bother walking down, it's not going to be the droid we're looking
	 * for.
	 */
	if (btrfs_header_bytenr(eb) != info->bytenr ||
	    btrfs_header_owner(eb) != info->objectid) {
		info->bad_blocks++;
		free_extent_buffer_nocache(eb);
		return;
	}

	/*
	 * Here we can be a little looser with the requirements, this may be a
	 * decent root to go with.
	 */
	info->found_blocks++;
	if (btrfs_header_generation(eb) != info->generation ||
	    btrfs_header_level(eb) != info->level) {
		info->generation = btrfs_header_generation(eb);
		info->level = btrfs_header_level(eb);
		info->bad_blocks++;
	}
	get_tree_info(fs_info, eb, info);
	free_extent_buffer_nocache(eb);
}

/*
 * If the root doesn't have a backup root we can go ahead and scan the whole
 * file system and see if we can find a better fit.
 */
static int scan_for_best_root(struct btrfs_fs_info *fs_info,
			      struct root_info *info)
{
	struct block_info search = {}, *block_info;
	struct root_info cur, best;
	int ret;
	bool found = false;

	memcpy(&cur, info, sizeof(cur));
	memcpy(&best, info, sizeof(best));

	ret = populate_block_info_cache(fs_info, info->objectid);
	if (ret) {
		error("Couldn't populate block info cache");
		return ret;
	}

	search.generation = info->generation;
	search.level = info->level;

	/*
	 * Every time we find a new block we remove it from the tree, so we can
	 * just iterate over everything that matches our level.
	 */
	while ((block_info = find_best_block(fs_info, &search, NULL)) != NULL) {
		found = true;

		reset_root_info(&cur);
		cur.bytenr = block_info->bytenr;
		cur.generation = block_info->generation;
		cur.level = block_info->level;
		get_root_info(fs_info, &cur);
		if (compare_root_info(&best, &cur) < 0)
			memcpy(&best, &cur, sizeof(cur));
		free(block_info);
	}

	if (!found) {
		error("Couldn't find a valid root block for %llu, we're going to clear it and hope for the best",
		      info->objectid);
		return -EINVAL;
	}
	memcpy(info, &best, sizeof(best));
	return 0;
}

/*
 * This walks through the roots pointed to by the super and the backup roots and
 * determines which one is the least broken.
 */
static int find_best_root(struct btrfs_fs_info *fs_info,
			  struct root_info *info)
{
	struct root_info cur;
	struct root_info best = {};
	int best_index;
	int i;

	memcpy(&cur, info, sizeof(cur));
	get_root_info(fs_info, &cur);

	if (cur.bad_blocks == 0) {
		memcpy(info, &cur, sizeof(cur));
		return 0;
	}

	/* From here on out we need to update the root. */
	cur.update = 1;
	memcpy(&best, &cur, sizeof(cur));

	/*
	 * Go ahead and try the best backup root, we can loop through the other
	 * backup roots if this one doesn't pan out.
	 */
	best_index = btrfs_find_best_backup_root(fs_info->super_copy);
	reset_root_info(&cur);
	get_backup_root_info(fs_info, &cur, best_index);

	/*
	 * We don't have this objectid in the backup roots, we need to scan the
	 * file system for possible roots and determine the best fit from that.
	 */
	if (cur.bytenr == (u64)-1) {
		int ret = scan_for_best_root(fs_info, &cur);
		memcpy(info, &cur, sizeof(cur));
		return ret;
	}

	get_root_info(fs_info, &cur);

	if (cur.bad_blocks == 0) {
		printf("Found completely clean tree for %llu in backup root, replacing\n",
		       info->objectid);
		memcpy(info, &cur, sizeof(cur));
		return 0;
	}

	if (compare_root_info(&best, &cur) < 0)
		memcpy(&best, &cur, sizeof(cur));

	/* Loop through the remaining backup roots. */
	for (i = 0; i < BTRFS_NUM_BACKUP_ROOTS; i++) {
		if (i == best_index)
			continue;
		reset_root_info(&cur);
		get_backup_root_info(fs_info, &cur, i);
		if (cur.bytenr == 0 || cur.bytenr == (u64)-1)
			continue;
		get_root_info(fs_info, &cur);
		if (compare_root_info(&best, &cur) < 0)
			memcpy(&best, &cur, sizeof(cur));
	}
	memcpy(info, &best, sizeof(best));
	return 0;
}

static void delete_slot(struct extent_buffer *eb, int slot)
{
	u32 nritems = btrfs_header_nritems(eb);

	if (slot < nritems - 1)
		memmove_extent_buffer(eb,
			      btrfs_node_key_ptr_offset(slot),
			      btrfs_node_key_ptr_offset(slot + 1),
			      sizeof(struct btrfs_key_ptr) *
			      (nritems - slot - 1));
	nritems--;
	btrfs_set_header_nritems(eb, nritems);
	write_tree_block(NULL, eb->fs_info, eb);
}

static void rewrite_slot(struct extent_buffer *eb, int slot,
			 struct block_info *info)
{
	struct btrfs_disk_key disk_key;

	btrfs_cpu_key_to_disk(&disk_key, &info->first_key);
	btrfs_set_node_blockptr(eb, slot, info->bytenr);
	btrfs_set_node_ptr_generation(eb, slot, info->generation);
	btrfs_set_node_key(eb, &disk_key, slot);
	write_tree_block(NULL, eb->fs_info, eb);
}

static int repair_tree(struct btrfs_fs_info *fs_info, struct extent_buffer *eb)
{
	struct btrfs_key prev_last = {};
	struct block_info *info;
	int start = 0;
	int i, ret = 0;

again:
	for (i = start; i < btrfs_header_nritems(eb); i++) {
		struct extent_buffer *tmp;
		struct btrfs_key first_key;
		u64 bytenr = btrfs_node_blockptr(eb, i);

		tmp = read_tree_block(fs_info, bytenr, 0);
		if (IS_ERR(tmp)) {
			int ret = PTR_ERR(tmp);
			if (ret == -ENOMEM)
				return ret;
			tmp = NULL;
		}
		if (!tmp || !is_good_block(eb, tmp, i)) {
			struct block_info search = {};

			free_extent_buffer_nocache(tmp);

			search.generation = btrfs_node_ptr_generation(eb, i);
			search.level = btrfs_header_level(eb) - 1;
			btrfs_node_key_to_cpu(eb, &search.first_key, i);
			if (i < (btrfs_header_nritems(eb) - 1))
				btrfs_node_key_to_cpu(eb, &search.last_key, i + 1);

			info = find_best_block(fs_info, &search, &prev_last);
			if (!info) {
//				fprintf(stderr, "deleting slot %d in block %llu\n",
//					i, eb->start);
				delete_slot(eb, i);
			} else {
//				fprintf(stderr, "updating slot %d in block %llu\n",
//					i, eb->start);
				rewrite_slot(eb, i, info);
				free(info);
			}
			start = i;
			goto again;
		}

		if (!btrfs_header_level(tmp)) {
			free_extent_buffer_nocache(tmp);
			continue;
		}
		btrfs_node_key_to_cpu(tmp, &first_key, 0);
		btrfs_node_key_to_cpu(tmp, &prev_last,
				      btrfs_header_nritems(tmp) - 1);
		ret = repair_tree(fs_info, tmp);
		if (ret) {
			free_extent_buffer_nocache(tmp);
			break;
		}

		/*
		 * At this point we don't need prev last, load the 0 node key
		 * from tmp as it is currently in case we had to delete that
		 * slot so we can update our pointer if we need to.
		 */
		btrfs_node_key_to_cpu(tmp, &prev_last, 0);
		if (btrfs_comp_cpu_keys(&first_key, &prev_last)) {
			struct btrfs_disk_key disk_key;

			btrfs_cpu_key_to_disk(&disk_key, &prev_last);
			btrfs_set_node_key(eb, &disk_key, i);
			write_tree_block(NULL, fs_info, eb);
		}
		free_extent_buffer_nocache(tmp);
	}
	return ret;
}

static int repair_root(struct btrfs_fs_info *fs_info, struct root_info *info)
{
	struct extent_buffer *eb;
	int ret;

	ret = populate_block_info_cache(fs_info, info->objectid);
	if (ret) {
		error("Couldn't populate block info cache");
		return ret;
	}

	eb = read_tree_block(fs_info, info->bytenr, 0);
	if (!eb || IS_ERR(eb)) {
		error("Failed to read root block");
		return -1;
	}

	ret = repair_tree(fs_info, eb);
	free_extent_buffer_nocache(eb);
	free_block_cache_tree(&block_cache);
	return ret;
}

static void rescue_fixup_low_keys(struct btrfs_path *path)
{
	struct btrfs_disk_key disk_key;
	int i;

	btrfs_item_key(path->nodes[0], &disk_key, 0);

	for (i = 1; i < BTRFS_MAX_LEVEL; i++) {
		int tslot = path->slots[i];
		if (!path->nodes[i])
			break;
		btrfs_set_node_key(path->nodes[i], &disk_key, tslot);
		write_tree_block(NULL, fs_info, path->nodes[i]);
		if (tslot != 0)
			break;
	}
}

static void delete_root(struct btrfs_path *path, int slot)
{
	struct extent_buffer *leaf;
	struct btrfs_item *item;
	int last_off;
	int dsize;
	int i;
	int nritems;

	leaf = path->nodes[0];
	last_off = btrfs_item_offset_nr(leaf, slot);
	dsize = btrfs_item_size_nr(leaf, slot);

	nritems = btrfs_header_nritems(leaf);

	if (slot != nritems) {
		int data_end = leaf_data_end(leaf);

		memmove_extent_buffer(leaf, btrfs_leaf_data(leaf) +
			      data_end + dsize,
			      btrfs_leaf_data(leaf) + data_end,
			      last_off - data_end);

		for (i = slot + 1; i < nritems; i++) {
			u32 ioff;

			item = btrfs_item_nr(i);
			ioff = btrfs_item_offset(leaf, item);
			btrfs_set_item_offset(leaf, item, ioff + dsize);
		}

		memmove_extent_buffer(leaf, btrfs_item_nr_offset(slot),
			      btrfs_item_nr_offset(slot + 1),
			      sizeof(struct btrfs_item) *
			      (nritems - slot - 1));
	}
	btrfs_set_header_nritems(leaf, nritems - 1);

	if (slot == 0)
		rescue_fixup_low_keys(path);
	write_tree_block(NULL, fs_info, path->nodes[0]);
}

/*
 * At this point the tree_root should be more or less valid, lets walk through
 * the root items and validate them.
 */
static int process_root_items(struct btrfs_fs_info *fs_info)
{
	struct btrfs_key key = { .type = BTRFS_ROOT_ITEM_KEY };
	struct btrfs_path path;
	int ret;

	btrfs_init_path(&path);

	ret = btrfs_search_slot(NULL, fs_info->tree_root, &key, &path, 0, 0);
	if (ret < 0) {
		error("Couldn't search tree root?\n");
		return ret;
	}
again:
	do {
		struct btrfs_key found_key;
		struct root_info info = {};
		struct btrfs_root_item *ri;

		btrfs_item_key_to_cpu(path.nodes[0], &found_key,
				      path.slots[0]);
		if (found_key.type != BTRFS_ROOT_ITEM_KEY)
			continue;

		ri = btrfs_item_ptr(path.nodes[0], path.slots[0],
				    struct btrfs_root_item);
		info.bytenr = btrfs_disk_root_bytenr(path.nodes[0], ri);
		info.generation = btrfs_disk_root_generation(path.nodes[0], ri);
		info.level = btrfs_disk_root_level(path.nodes[0], ri);
		info.objectid = found_key.objectid;

		printf("Checking root %llu\n", found_key.objectid);
		if (info.objectid == 10)
			printf("searching for fst at level %d\n", info.level);
		ret = find_best_root(fs_info, &info);
		if (ret) {
			printf("We thought root %llu could be found at %llu level %d but didn't find anything, deleting it.\n",
			       found_key.objectid, info.bytenr, info.level);
			delete_root(&path, path.slots[0]);
			goto again;
		}

		if (info.bad_blocks) {
			ret = repair_root(fs_info, &info);
			if (ret)
				break;
		}

		if (info.bad_blocks || info.update) {
			printf("Updating root %llu\n", found_key.objectid);
			btrfs_set_disk_root_bytenr(path.nodes[0], ri,
						   info.bytenr);
			btrfs_set_disk_root_generation(path.nodes[0], ri,
						       info.generation);
			btrfs_set_disk_root_level(path.nodes[0], ri,
						  info.level);
			write_tree_block(NULL, fs_info, path.nodes[0]);
		}
		free_block_cache_tree(&block_cache);
	} while ((ret = btrfs_next_item(fs_info->tree_root, &path)) == 0);

	if (ret > 0)
		ret = 0;

	btrfs_release_path(&path);
	return ret;
}

int btrfs_recover_trees(const char *path)
{
	struct btrfs_fs_info *fs_info;
	struct root_info info = {};
	struct open_ctree_flags ocf = {};
	int ret = 0;
	bool repair_chunk = false;
	bool repair_tree = false;

	extent_io_tree_init(&seen);

	ocf.filename = path;
	ocf.flags = OPEN_CTREE_CHUNK_ROOT_ONLY | OPEN_CTREE_WRITES |
		OPEN_CTREE_ALLOW_TRANSID_MISMATCH;
again:
	fs_info = open_ctree_fs_info(&ocf);
	if (!fs_info) {
		error("open ctree failed");
		return -1;
	}

	fs_info->suppress_check_block_errors = 1;

	/*
	 * We need to check the chunk root first, if it's messed up we'll have a
	 * bad time with everything else.
	 */
	info.objectid = BTRFS_CHUNK_TREE_OBJECTID;
	btrfs_get_super_root_info(fs_info, BTRFS_CHUNK_TREE_OBJECTID,
				  &info.bytenr, &info.generation, &info.level);
	ret = find_best_root(fs_info, &info);
	if (ret)
		goto out;

	/* We had some bad blocks, go ahead and repair this tree first. */
	if (info.bad_blocks) {
		if (repair_chunk) {
			error("Still found bad blocks after a repair loop, bailing");
			ret = -1;
			goto out;
		}
		ret = repair_root(fs_info, &info);
		if (ret)
			goto out;
		close_ctree_fs_info(fs_info);
		repair_chunk = true;
		goto again;
	} else if (info.update) {
		if (repair_chunk) {
			error("Still have update after a repair loop, bailing");
			ret = -1;
			goto out;
		}
		/*
		 * We may have found a pristine backup root, so go ahead and
		 * update the super and go again.
		 */
		btrfs_set_super_chunk_root(fs_info->super_copy, info.bytenr);
		btrfs_set_super_chunk_root_level(fs_info->super_copy,
						 info.level);
		btrfs_set_super_chunk_root_generation(fs_info->super_copy,
						      info.generation);
		ret = write_all_supers(fs_info);
		if (ret) {
			error("Couldn't write super blocks");
			goto out;
		}
		close_ctree_fs_info(fs_info);
		repair_chunk = true;
		goto again;
	}

	reset_root_info(&info);
	info.objectid = BTRFS_ROOT_TREE_OBJECTID;
	btrfs_get_super_root_info(fs_info, BTRFS_ROOT_TREE_OBJECTID,
				  &info.bytenr, &info.generation, &info.level);
	ret = find_best_root(fs_info, &info);
	if (ret)
		goto out;

	if (info.bad_blocks) {
		if (repair_tree) {
			error("Still found bad blocks in tree root after repair, bailing");
			ret = -1;
			goto out;
		}
		ret = repair_root(fs_info, &info);
		if (ret)
			goto out;
		close_ctree_fs_info(fs_info);
		repair_tree = true;
		goto again;
	} else if (info.update) {
		if (repair_tree) {
			error("Still have to update the tree root after repair, bailing");
			ret = -1;
			goto out;
		}
		btrfs_set_super_generation(fs_info->super_copy,
					   info.generation);
		btrfs_set_super_root(fs_info->super_copy, info.bytenr);
		btrfs_set_super_root_level(fs_info->super_copy, info.level);
		ret = write_all_supers(fs_info);
		if (ret) {
			error("Couldn't write super blocks");
			goto out;
		}
		close_ctree_fs_info(fs_info);
		repair_tree = true;
		goto again;
	}

	ret = process_root_items(fs_info);
out:
	close_ctree_fs_info(fs_info);
	btrfs_close_all_devices();
	extent_io_tree_cleanup(&seen);
	return ret;
}
