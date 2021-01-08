/*
 * Copyright (C) 2021 Facebook.  All rights reserved.
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

#include <stdio.h>
#include "kernel-shared/ctree.h"
#include "kernel-shared/disk-io.h"
#include "kernel-shared/transaction.h"
#include "kernel-shared/volumes.h"
#include "common/rbtree-utils.c"
#include "check/common.h"
#include "check/mode-common.h"

static struct rb_root corrupt_root = RB_ROOT;
static LIST_HEAD(reinit_roots);
static struct extent_io_tree *visited = NULL;

struct corrupt_record {
	u64 bytenr;
	struct btrfs_key key;
	u64 *roots;
	int nr_roots;
	int level;
	struct rb_node node;
	enum btrfs_tree_block_status status;
};

struct corrupt_root {
	struct btrfs_key key;
	struct list_head list;
};

static int add_bad_root(struct btrfs_key *key)
{
	struct corrupt_root *cr = malloc(sizeof(struct corrupt_root));
	if (!cr)
		return -ENOMEM;
	fprintf(stderr, "Adding a corrupt root record for %llu\n",
		key->objectid);
	memcpy(&cr->key, key, sizeof(struct btrfs_key));
	list_add_tail(&cr->list, &reinit_roots);
	return 0;
}

static int corrupt_record_compare(struct rb_node *node1, struct rb_node *node2)
{
	struct corrupt_record *rec1, *rec2;

	rec1 = rb_entry(node1, struct corrupt_record, node);
	rec2 = rb_entry(node2, struct corrupt_record, node);
	if (rec1->bytenr > rec2->bytenr)
		return -1;
	else if (rec1->bytenr < rec2->bytenr)
		return 1;
	return 0;
}

static int corrupt_record_key_compare(struct rb_node *n, void *k)
{
	u64 bytenr = *(u64 *)k;
	struct corrupt_record *rec = rb_entry(n, struct corrupt_record, node);

	if (rec->bytenr > bytenr)
		return -1;
	else if (rec->bytenr < bytenr)
		return 1;
	return 0;
}

static void free_corrupt_record(struct corrupt_record *rec)
{
	free(rec->roots);
	free(rec);
}

static int add_corrupt_record(struct extent_buffer *eb, u64 bytenr, u64 root_id,
			      int slot, enum btrfs_tree_block_status status)
{
	struct corrupt_record *rec;

	fprintf(stderr,
"Adding corrupt record for %llu in node %llu slot %d level %d root %llu\n",
		bytenr, eb->start, slot, btrfs_header_level(eb), root_id);

	rec = calloc(1, sizeof(struct corrupt_record));
	if (!rec)
		return -ENOMEM;
	rec->roots = calloc(1, sizeof(u64));
	if (!rec->roots) {
		free(rec);
		return -ENOMEM;
	}

	rec->bytenr = bytenr;
	rec->nr_roots = 1;
	rec->roots[0] = root_id;
	rec->level = btrfs_header_level(eb);
	rec->status = status;

	if (btrfs_header_level(eb))
		btrfs_node_key_to_cpu(eb, &rec->key, slot);
	else
		btrfs_item_key_to_cpu(eb, &rec->key, slot);

	if (rb_insert(&corrupt_root, &rec->node, corrupt_record_compare)) {
		fprintf(stderr, "We had a duplicate for %llu already?\n",
			eb->start);
		free_corrupt_record(rec);
		return -EINVAL;
	}
	return 0;
}

/*
 * If we have already processed a block we need to check and see if there was an
 * existing bad link for this buffer, and if so add our root_id to the list so
 * we know to delete the record in this root as well.
 */
static int check_for_corrupt_record(u64 bytenr, u64 root_id, int slot)
{
	struct corrupt_record *rec;
	struct rb_node *n;
	u64 *tmp;

	n = rb_search(&corrupt_root, &bytenr, corrupt_record_key_compare,
		      NULL);
	if (!n)
		return 0;

	fprintf(stderr,
		"Adding root %llu to existing delete record at bytenr %llu\n",
		root_id, bytenr);

	rec = rb_entry(n, struct corrupt_record, node);
	rec->nr_roots++;
	tmp = reallocarray(rec->roots, rec->nr_roots, sizeof(u64));
	if (!tmp) {
		fprintf(stderr, "Couldn't expand the roots list for %llu\n",
			bytenr);
		return -ENOMEM;
	}
	rec->roots = tmp;
	rec->roots[rec->nr_roots - 1] = root_id;

	return 0;
}

/*
 * Basic sanity checks on the block.
 */
static int check_block(struct extent_buffer *eb, u64 root_id, int level)
{
	/*
	 * We got caught by the normal checking from the read, we know this
	 * thing is already toast, kick it back.
	 */
	if (!extent_buffer_uptodate(eb)) {
		fprintf(stderr, "extent buffer wasn't uptodate\n");
		return -1;
	}

	/*
	 * !fstree blocks should always match the root_id, fs_tree's can
	 * obviously point at nodes or leaves that don't belong to them.
	 */
	if (!is_fstree(root_id) && btrfs_header_owner(eb) != root_id) {
		fprintf(stderr, "non fs tree that didn't match the owner\n");
		return -1;
	}

	/*
	 * If we are an fstree then we shouldn't be pointing at a block that
	 * isn't owned by a fstree.
	 */
	if (is_fstree(root_id) && !is_fstree(btrfs_header_owner(eb))) {
		fprintf(stderr, "fs tree that points at a non-fs tree block\n");
		return -1;
	}

	/* A sanity check to make sure we're the level we expect. */
	if (btrfs_header_level(eb) != level) {
		fprintf(stderr, "level didn't match the expected level\n");
		return -1;
	}
	return 0;
}

static int validate_block(struct btrfs_fs_info *fs_info,
			  struct extent_buffer *parent,
			  struct extent_buffer *eb, u64 root_id, int slot)
{
	u64 bytenr = btrfs_node_blockptr(parent, slot);
	struct btrfs_disk_key key;
	enum btrfs_tree_block_status status = BTRFS_TREE_BLOCK_CLEAN;
	int ret = 0;

	/*
	 * We set CLEAN here so that the repair code knows it's not something we
	 * can deal with and we should just delete the link to the node.
	 */
	if (IS_ERR(eb)) {
		if (PTR_ERR(eb) != -EIO)
			return PTR_ERR(eb);
		goto bad;
	}

	/*
	 * Since we're reading one block at a time we miss the parent key checks
	 * that would normally be run, so do this here.  This is an area where
	 * we could do better and just change the parent key to match the child
	 * key since everything else appears to be kosher, but for now just
	 * delete the link.
	 */
	btrfs_node_key(parent, &key, slot);
	if (btrfs_header_level(eb))
		status = btrfs_check_node(fs_info, &key, eb);
	else
		status = btrfs_check_leaf(fs_info, &key, eb);
	if (status != BTRFS_TREE_BLOCK_CLEAN)
		goto bad;

	if (check_block(eb, root_id, btrfs_header_level(parent) - 1))
		goto bad;

	return 0;
bad:
	set_extent_dirty(visited, bytenr, bytenr + fs_info->nodesize - 1);
	ret = add_corrupt_record(parent, bytenr, root_id, slot, status);
	if (!ret)
		ret = 1;
	return ret;
}

static int validate_root_item(struct btrfs_fs_info *fs_info,
			      struct extent_buffer *parent,
			      struct extent_buffer *eb, int slot)
{
	struct btrfs_root_item *ri;
	struct btrfs_key key;
	u64 bytenr;
	int ret;

	btrfs_item_key_to_cpu(parent, &key, slot);
	ri = btrfs_item_ptr(parent, slot, struct btrfs_root_item);
	bytenr = btrfs_disk_root_bytenr(parent, ri);

	if (IS_ERR(eb)) {
		if (PTR_ERR(eb) != -EIO)
			return PTR_ERR(eb);
		goto bad;
	}

	if (check_block(eb, key.objectid, btrfs_disk_root_level(parent, ri)))
		goto bad;

	/* The owner of the root node should always match the root objectid */
	if (btrfs_header_owner(eb) != key.objectid) {
		fprintf(stderr,
"root item pointed at a block that had an owner of %llu\n",
			btrfs_header_owner(eb));
		goto bad;
	}
	return 0;
bad:
	set_extent_dirty(visited, bytenr, bytenr + fs_info->nodesize - 1);
	ret = add_bad_root(&key);
	if (ret)
		return ret;
	return 1;
}

/*
 * This recursively walks down a tree looking for bad nodes.  If we're the tree
 * root it'll walk into any root item that it finds.
 */
static int validate_tree_blocks(struct btrfs_fs_info *fs_info,
				struct extent_buffer *eb, u64 root_id)
{
	struct extent_buffer *tmp;
	u64 end = eb->start + eb->len, bytenr;
	int nritems;
	int ret = 0;
	int i;

	if (test_range_bit(visited, eb->start, end - 1, EXTENT_DIRTY, 0)) {
		/*
		 * If we have already processed this block, we could potentially
		 * have a delete record for a slot here that we recorded via a
		 * different root.  Check for this case and add this root so we
		 * can make sure to delete any references to a bad block.
		 */
		nritems = btrfs_header_nritems(eb);
		for (i = 0; i < nritems; i++) {
			bytenr = btrfs_node_blockptr(eb, i);
			ret = check_for_corrupt_record(bytenr, root_id, i);
			if (ret < 0)
				return ret;
		}
		return 0;
	}

	set_extent_dirty(visited, eb->start, end - 1);

	/* We don't need to process the leaf's of other trees. */
	if (btrfs_header_level(eb) == 0 &&
	    btrfs_header_owner(eb) != BTRFS_ROOT_TREE_OBJECTID)
		return 0;

	nritems = btrfs_header_nritems(eb);
	for (i = 0; i < nritems; i++) {
		if (btrfs_header_level(eb) == 0) {
			struct btrfs_key key;
			struct btrfs_root_item *ri;

			btrfs_item_key_to_cpu(eb, &key, i);
			if (key.type != BTRFS_ROOT_ITEM_KEY)
				continue;
			ri = btrfs_item_ptr(eb, i, struct btrfs_root_item);
			bytenr = btrfs_disk_root_bytenr(eb, ri);

			tmp = read_tree_block(fs_info, bytenr, 0);
			ret = validate_root_item(fs_info, eb, tmp, i);
			if (ret) {
				free_extent_buffer(tmp);
				if (ret < 0)
					break;
				ret = 0;
				continue;
			}

			ret = validate_tree_blocks(fs_info, tmp, key.objectid);
			free_extent_buffer(tmp);
			if (ret)
				break;
		} else {
			bytenr = btrfs_node_blockptr(eb, i);
			end = bytenr + fs_info->nodesize - 1;

			/*
			 * If we've already processed this block just check for
			 * a delete record and carry on.
			 */
			if (test_range_bit(visited, bytenr, end, EXTENT_DIRTY,
					   0)) {
				ret = check_for_corrupt_record(bytenr, root_id,
							       i);
				if (ret)
					break;
				continue;
			}

			tmp = read_tree_block(fs_info, bytenr, 0);
			ret = validate_block(fs_info, eb, tmp, root_id, i);
			if (ret) {
				free_extent_buffer(tmp);
				if (ret < 0)
					break;
				ret = 0;
				continue;
			}

			ret = validate_tree_blocks(fs_info, tmp, root_id);
			free_extent_buffer(tmp);
			if (ret)
				break;
		}
	}
	return ret;
}

static int swap_values(struct btrfs_root *root, struct btrfs_path *path,
		       struct extent_buffer *buf, int slot)
{
	if (btrfs_header_level(buf)) {
		struct btrfs_key_ptr ptr1, ptr2;

		read_extent_buffer(buf, &ptr1, btrfs_node_key_ptr_offset(slot),
				   sizeof(struct btrfs_key_ptr));
		read_extent_buffer(buf, &ptr2,
				   btrfs_node_key_ptr_offset(slot + 1),
				   sizeof(struct btrfs_key_ptr));
		write_extent_buffer(buf, &ptr1,
				    btrfs_node_key_ptr_offset(slot + 1),
				    sizeof(struct btrfs_key_ptr));
		write_extent_buffer(buf, &ptr2,
				    btrfs_node_key_ptr_offset(slot),
				    sizeof(struct btrfs_key_ptr));
		if (slot == 0) {
			struct btrfs_disk_key key;

			btrfs_node_key(buf, &key, 0);
			btrfs_fixup_low_keys(root, path, &key,
					     btrfs_header_level(buf) + 1);
		}
	} else {
		struct btrfs_item *item1, *item2;
		struct btrfs_key k1, k2;
		char *item1_data, *item2_data;
		u32 item1_offset, item2_offset, item1_size, item2_size;

		item1 = btrfs_item_nr(slot);
		item2 = btrfs_item_nr(slot + 1);
		btrfs_item_key_to_cpu(buf, &k1, slot);
		btrfs_item_key_to_cpu(buf, &k2, slot + 1);
		item1_offset = btrfs_item_offset(buf, item1);
		item2_offset = btrfs_item_offset(buf, item2);
		item1_size = btrfs_item_size(buf, item1);
		item2_size = btrfs_item_size(buf, item2);

		item1_data = malloc(item1_size);
		if (!item1_data)
			return -ENOMEM;
		item2_data = malloc(item2_size);
		if (!item2_data) {
			free(item1_data);
			return -ENOMEM;
		}

		read_extent_buffer(buf, item1_data, item1_offset, item1_size);
		read_extent_buffer(buf, item2_data, item2_offset, item2_size);

		write_extent_buffer(buf, item1_data, item2_offset, item2_size);
		write_extent_buffer(buf, item2_data, item1_offset, item1_size);
		free(item1_data);
		free(item2_data);

		btrfs_set_item_offset(buf, item1, item2_offset);
		btrfs_set_item_offset(buf, item2, item1_offset);
		btrfs_set_item_size(buf, item1, item2_size);
		btrfs_set_item_size(buf, item2, item1_size);

		path->slots[0] = slot;
		btrfs_set_item_key_unsafe(root, path, &k2);
		path->slots[0] = slot + 1;
		btrfs_set_item_key_unsafe(root, path, &k1);
	}
	return 0;
}

static int fix_key_order(struct btrfs_root *root, struct btrfs_path *path)
{
	struct extent_buffer *buf;
	struct btrfs_key k1, k2;
	int i;
	int level = path->lowest_level;
	int ret = -EIO;

	buf = path->nodes[level];
	for (i = 0; i < btrfs_header_nritems(buf) - 1; i++) {
		if (level) {
			btrfs_node_key_to_cpu(buf, &k1, i);
			btrfs_node_key_to_cpu(buf, &k2, i + 1);
		} else {
			btrfs_item_key_to_cpu(buf, &k1, i);
			btrfs_item_key_to_cpu(buf, &k2, i + 1);
		}
		if (btrfs_comp_cpu_keys(&k1, &k2) < 0)
			continue;
		ret = swap_values(root, path, buf, i);
		if (ret)
			break;
		btrfs_mark_buffer_dirty(buf);
		i = 0;
	}
	return ret;
}

static int delete_bogus_item(struct btrfs_root *root,
			     struct btrfs_path *path,
			     struct extent_buffer *buf, int slot)
{
	struct btrfs_key key;
	int nritems = btrfs_header_nritems(buf);

	btrfs_item_key_to_cpu(buf, &key, slot);

	/* These are all the keys we can deal with missing. */
	if (key.type != BTRFS_DIR_INDEX_KEY &&
	    key.type != BTRFS_EXTENT_ITEM_KEY &&
	    key.type != BTRFS_METADATA_ITEM_KEY &&
	    key.type != BTRFS_TREE_BLOCK_REF_KEY &&
	    key.type != BTRFS_EXTENT_DATA_REF_KEY)
		return -1;

	printf("Deleting bogus item [%llu,%u,%llu] at slot %d on block %llu\n",
	       (unsigned long long)key.objectid, key.type,
	       (unsigned long long)key.offset, slot, buf->start);
	memmove_extent_buffer(buf, btrfs_item_nr_offset(slot),
			      btrfs_item_nr_offset(slot + 1),
			      sizeof(struct btrfs_item) *
			      (nritems - slot - 1));
	btrfs_set_header_nritems(buf, nritems - 1);
	if (slot == 0) {
		struct btrfs_disk_key disk_key;

		btrfs_item_key(buf, &disk_key, 0);
		btrfs_fixup_low_keys(root, path, &disk_key, 1);
	}
	btrfs_mark_buffer_dirty(buf);
	return 0;
}

static int fix_item_offset(struct btrfs_root *root, struct btrfs_path *path)
{
	struct extent_buffer *buf;
	int i;
	int ret = 0;

	/* We should only get this for leaves */
	BUG_ON(path->lowest_level);
	buf = path->nodes[0];
again:
	for (i = 0; i < btrfs_header_nritems(buf); i++) {
		unsigned int shift = 0, offset;

		if (i == 0 && btrfs_item_end_nr(buf, i) !=
		    BTRFS_LEAF_DATA_SIZE(gfs_info)) {
			if (btrfs_item_end_nr(buf, i) >
			    BTRFS_LEAF_DATA_SIZE(gfs_info)) {
				ret = delete_bogus_item(root, path, buf, i);
				if (!ret)
					goto again;
				fprintf(stderr,
				"item is off the end of the leaf, can't fix\n");
				ret = -EIO;
				break;
			}
			shift = BTRFS_LEAF_DATA_SIZE(gfs_info) -
				btrfs_item_end_nr(buf, i);
		} else if (i > 0 && btrfs_item_end_nr(buf, i) !=
			   btrfs_item_offset_nr(buf, i - 1)) {
			if (btrfs_item_end_nr(buf, i) >
			    btrfs_item_offset_nr(buf, i - 1)) {
				ret = delete_bogus_item(root, path, buf, i);
				if (!ret)
					goto again;
				fprintf(stderr, "items overlap, can't fix\n");
				ret = -EIO;
				break;
			}
			shift = btrfs_item_offset_nr(buf, i - 1) -
				btrfs_item_end_nr(buf, i);
		}
		if (!shift)
			continue;

		printf("Shifting item nr %d by %u bytes in block %llu\n",
		       i, shift, (unsigned long long)buf->start);
		offset = btrfs_item_offset_nr(buf, i);
		memmove_extent_buffer(buf,
				      btrfs_leaf_data(buf) + offset + shift,
				      btrfs_leaf_data(buf) + offset,
				      btrfs_item_size_nr(buf, i));
		btrfs_set_item_offset(buf, btrfs_item_nr(i),
				      offset + shift);
		btrfs_mark_buffer_dirty(buf);
	}

	/*
	 * We may have moved things, in which case we want to exit so we don't
	 * write those changes out.  Once we have proper abort functionality in
	 * progs this can be changed to something nicer.
	 */
	BUG_ON(ret);
	return ret;
}

static int fix_block_issue(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root,
			   struct corrupt_record *rec)
{
	struct btrfs_path path;
	int ret;

	/* The level points at the parent, so we need to go 1 down. */
	path.lowest_level = rec->level - 1;
	path.skip_check_block = 1;
	ret = btrfs_search_slot(trans, root, &rec->key, &path, 0, 1);
	if (ret) {
		ret = -EIO;
		return ret;
	}
	if (rec->status == BTRFS_TREE_BLOCK_BAD_KEY_ORDER)
		ret = fix_key_order(root, &path);
	else if (rec->status == BTRFS_TREE_BLOCK_INVALID_OFFSETS)
		ret = fix_item_offset(root, &path);
	btrfs_release_path(&path);
	return ret;
}

static int delete_block_reference(struct btrfs_trans_handle *trans,
				  struct btrfs_root *root,
				  struct corrupt_record *rec)
{
	struct btrfs_path path;
	struct btrfs_key key;
	int ret;

	printf("Deleting link to bytenr %llu in root %llu\n", rec->bytenr,
	       root->root_key.objectid);

	btrfs_init_path(&path);
	path.lowest_level = rec->level;
	ret = btrfs_search_slot(trans, root, &rec->key, &path, -1, 1);
	if (ret < 0) {
		fprintf(stderr,
			"Failed to search trying to delete %llu from root %llu %d\n",
			rec->bytenr, rec->key.objectid, ret);
		return ret;
	}

	btrfs_node_key_to_cpu(path.nodes[rec->level], &key,
			      path.slots[rec->level]);
	if (memcmp(&rec->key, &key, sizeof(key))) {
		fprintf(stderr,
			"Failed to find the right slot for a corrupt block?\n");
		ret = -EINVAL;
		goto out;
	}

	/*
	 * We are specifically not freeing the extent reference here because the
	 * extent tree could be corrupt already, and we don't want to mess
	 * things up worse by modifying the extent tree.
	 *
	 * In the future it may make sense to process any extent tree records
	 * that need to be deleted first, and then for everything else go ahead
	 * and do the btrfs_free_extent, so at least we're not making more work
	 * for ourselves.  But at this point I don't want to worry about
	 * tripping some other problem and causing us to bail out here.
	 */
	if (rec->level) {
		printf("deleting slot %d at level %d bytenr %llu which is %llu\n",
		       path.slots[rec->level], rec->level,
		       path.nodes[rec->level]->start,
		       btrfs_node_blockptr(path.nodes[rec->level],
					   path.slots[rec->level]));

		ret = btrfs_del_ptr(root, &path, rec->level,
				    path.slots[rec->level]);
		if (ret) {
			fprintf(stderr,
				"Couldn't delete pointer to %llu from root %llu\n",
				rec->bytenr, key.objectid);
			goto out;
		}
		btrfs_set_root_used(&root->root_item,
				    btrfs_root_used(&root->root_item) -
				    root->fs_info->nodesize);
	} else {
		ret = btrfs_del_item(trans, root, &path);
		if (ret) {
			fprintf(stderr,
				"Failed to delete the item in root %llu\n",
				key.objectid);
			goto out;
		}
	}
out:
	btrfs_release_path(&path);
	return ret;
}

/*
 * Walks through all of the roots that point to the corrupt block and removes
 * the block pointer for that specific node/leaf.
 */
static int repair_corrupt_record(struct btrfs_fs_info *fs_info,
				 struct corrupt_record *rec)
{
	struct btrfs_trans_handle *trans = NULL;
	struct btrfs_root *root;
	struct btrfs_key key;
	int i, ret = 0;

	for (i = 0; i < rec->nr_roots; i++) {
		key.objectid = rec->roots[i];
		key.type = BTRFS_ROOT_ITEM_KEY;
		key.offset = (u64)-1;

		root = btrfs_read_fs_root(fs_info, &key);
		if (IS_ERR(root)) {
			fprintf(stderr, "Couldn't read root %llu\n",
				key.objectid);
			return PTR_ERR(root);
		}

		trans = btrfs_start_transaction(root, 1);
		if (IS_ERR(trans))
			return PTR_ERR(trans);

		switch(rec->status) {
		case BTRFS_TREE_BLOCK_BAD_KEY_ORDER:
		case BTRFS_TREE_BLOCK_INVALID_OFFSETS:
			ret = fix_block_issue(trans, root, rec);
			break;
		default:
			ret = delete_block_reference(trans, root, rec);
			break;
		}
		if (ret)
			goto abort;

		btrfs_commit_transaction(trans, root);
	}
	return 0;
abort:
	btrfs_abort_transaction(trans, ret);
	btrfs_commit_transaction(trans, root);
	return ret;
}

static int delete_corrupt_records(struct btrfs_fs_info *fs_info)
{
	struct corrupt_record *rec;
	struct rb_node *n;
	int ret = 0;

	if (RB_EMPTY_ROOT(&corrupt_root))
		return 0;

	printf("Processing corrupt records\n");
	while ((n = rb_first(&corrupt_root)) != NULL) {
		rec = rb_entry(n, struct corrupt_record, node);
		rb_erase(n, &corrupt_root);
		if (!ret)
			ret = repair_corrupt_record(fs_info, rec);
		free_corrupt_record(rec);
	}
	return ret;
}

/*
 * For global roots, like the extent tree, we can't just delete the root item.
 * Instead zero out the root, and then let fsck figure out how to put it all
 * back together again.
 */
static int reinit_root(struct btrfs_fs_info *fs_info, struct btrfs_key *key)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root;
	struct extent_buffer *c;
	struct btrfs_root_item ri = {};
	struct btrfs_disk_key disk_key = {};
	int ret = 0;

	fprintf(stderr, "Reinit'ing root %llu\n", key->objectid);

	trans = btrfs_start_transaction(fs_info->tree_root, 1);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	c = btrfs_alloc_free_block(trans, fs_info->tree_root,
				   fs_info->nodesize, key->objectid, &disk_key,
				   0, 0, 0);
	if (IS_ERR(c)) {
		btrfs_abort_transaction(trans, PTR_ERR(trans));
		return PTR_ERR(trans);
	}

	memset_extent_buffer(c, 0, 0, sizeof(struct btrfs_header));
	btrfs_set_header_level(c, 0);
	btrfs_set_header_bytenr(c, c->start);
	btrfs_set_header_generation(c, trans->transid);
	btrfs_set_header_backref_rev(c, BTRFS_MIXED_BACKREF_REV);
	btrfs_set_header_owner(c, key->objectid);

	write_extent_buffer(c, fs_info->fs_devices->metadata_uuid,
			    btrfs_header_fsid(), BTRFS_FSID_SIZE);
	write_extent_buffer(c, fs_info->chunk_tree_uuid,
			    btrfs_header_chunk_tree_uuid(c),
			    BTRFS_UUID_SIZE);
	btrfs_mark_buffer_dirty(c);

	btrfs_set_root_bytenr(&ri, c->start);
	btrfs_set_root_generation(&ri, trans->transid);
	btrfs_set_root_refs(&ri, 1);
	btrfs_set_root_used(&ri, fs_info->nodesize);
	ret = btrfs_update_root(trans, fs_info->tree_root, key, &ri);
	if (ret) {
		btrfs_abort_transaction(trans, ret);
		goto out;
	}
	btrfs_commit_transaction(trans, fs_info->tree_root);

	/*
	 * Just in case we already cached this root, we need to fix where
	 * everything is pointing.
	 */
	key->offset = (u64)-1;
	root = btrfs_read_fs_root(fs_info, key);
	if (IS_ERR(root)) {
		fprintf(stderr, "Couldn't read root after init'ing\n");
		ret = PTR_ERR(root);
		goto out;
	}

	if (root->node->start != c->start) {
		memcpy(&root->root_item, &ri, sizeof(ri));
		free_extent_buffer(root->node);
		root->node = c;
		c->refs++;
	}
out:
	free_extent_buffer(c);
	return ret;
}

/*
 * Currently we simply delete fs roots that point at a broken leaf.  restore
 * should have already been run and a best effort been made.  In the future we
 * could do something smarter but for now just remove the root.
 */
static int handle_bad_fs_root(struct btrfs_fs_info *fs_info,
			      struct btrfs_key *key)
{
	struct btrfs_trans_handle *trans;
	int ret;

	fprintf(stderr, "Deleting bad fs root %llu\n", key->objectid);
	trans = btrfs_start_transaction(fs_info->tree_root, 1);
	if (IS_ERR(trans))
		return PTR_ERR(trans);
	ret = btrfs_del_root(trans, fs_info->tree_root, key);
	if (ret) {
		fprintf(stderr, "failed to delete fs root %d\n", ret);
		btrfs_abort_transaction(trans, ret);
	}
	btrfs_commit_transaction(trans, fs_info->tree_root);
	return ret;
}

static int reinit_broken_roots(struct btrfs_fs_info *fs_info)
{
	int ret = 0;

	while (!list_empty(&reinit_roots)) {
		struct corrupt_root *cr = list_first_entry(&reinit_roots,
							   struct corrupt_root,
							   list);
		list_del_init(&cr->list);
		if (!ret) {
			if (is_fstree(cr->key.objectid))
				ret = handle_bad_fs_root(fs_info, &cr->key);
			else
				ret = reinit_root(fs_info, &cr->key);
		}
		free(cr);
	}
	return ret;
}

/**
 * validate_and_repair_tree_structure - validate all referenced tree blocks
 * @fs_info: the fs_info for the fs.
 *
 * This walks down all referenced tree blocks in the file system and fixes any
 * problems it finds.  There are two classes of problems we're looking for.
 *
 * 1. corrupt nodes/leafs.  The current strategy is to simply remove references
 *    to any node/leaf that is corrupt.  In the future we could be smarter than
 *    this by trying to fix specific problems, but for now simply remove them.
 *
 * 2. handle root items that point at corrupt nodes/leafs.  If the root points
 *    at a corrupt node or leaf then we need to handle that by either
 *    re-initializing the root (in the case of a global root) or removing the
 *    root item (in the case of an fs root).  Again something more intelligent
 *    could be done in the future, but right now scorched earth is the easiest
 *    to deal with.
 */
int validate_and_repair_root(struct btrfs_fs_info *fs_info,
			     struct btrfs_root *root)
{
	int ret;

	if (!visited) {
		visited = malloc(sizeof(struct extent_io_tree));
		if (!visited)
			return -ENOMEM;
		extent_io_tree_init(visited);
	}

	ret = validate_tree_blocks(fs_info, root->node,
				   root->root_key.objectid);
	if (ret)
		return ret;

	ret = delete_corrupt_records(fs_info);
	if (ret)
		return ret;

	return reinit_broken_roots(fs_info);
}
