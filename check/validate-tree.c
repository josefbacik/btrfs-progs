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

struct corrupt_record_key {
	u64 bytenr;
	int slot;
};

struct corrupt_record {
	struct corrupt_record_key rec_key;
	int slot;
	struct btrfs_key key;
	u64 *roots;
	int nr_roots;
	int level;
	struct rb_node node;
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
	if (rec1->rec_key.bytenr > rec2->rec_key.bytenr)
		return -1;
	else if (rec1->rec_key.bytenr < rec2->rec_key.bytenr)
		return 1;
	if (rec1->rec_key.slot > rec2->rec_key.slot)
		return -1;
	else if (rec1->rec_key.slot < rec2->rec_key.slot)
		return 1;
	return 0;
}

static int corrupt_record_key_compare(struct rb_node *n, void *k)
{
	struct corrupt_record_key *key = (struct corrupt_record_key *)k;
	struct corrupt_record *rec = rb_entry(n, struct corrupt_record, node);

	if (rec->rec_key.bytenr > key->bytenr)
		return -1;
	else if (rec->rec_key.bytenr < key->bytenr)
		return 1;
	if (rec->rec_key.slot > key->slot)
		return -1;
	else if (rec->rec_key.slot < key->slot)
		return 1;
	return 0;
}

static void free_corrupt_record(struct corrupt_record *rec)
{
	free(rec->roots);
	free(rec);
}

static int add_corrupt_record(struct extent_buffer *eb, u64 bytenr, u64 root_id,
			      int slot)
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

	rec->rec_key.bytenr = bytenr;
	rec->rec_key.slot = slot;
	rec->nr_roots = 1;
	rec->roots[0] = root_id;
	rec->level = btrfs_header_level(eb);

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
	struct corrupt_record_key key = {
		.bytenr = bytenr,
		.slot = slot,
	};
	struct corrupt_record *rec;
	struct rb_node *n;
	u64 *tmp;

	n = rb_search(&corrupt_root, &key, corrupt_record_key_compare, NULL);
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
	int ret;

	if (check_block(eb, root_id, btrfs_header_level(parent) - 1))
		goto bad;

	/*
	 * Since we're reading one block at a time we miss the parent key checks
	 * that would normally be run, so do this here.  This is an area where
	 * we could do better and just change the parent key to match the child
	 * key since everything else appears to be kosher, but for now just
	 * delete the link.
	 */
	btrfs_node_key(parent, &key, slot);
	if (btrfs_header_level(eb)) {
		if (btrfs_check_node(fs_info, &key, eb))
			goto bad;
	} else if (btrfs_check_leaf(fs_info, &key, eb)) {
		goto bad;
	}
	return 0;
bad:
	set_extent_dirty(fs_info->excluded_extents, bytenr,
			 bytenr + fs_info->nodesize - 1);
	ret = add_corrupt_record(parent, bytenr, root_id, slot);
	if (ret)
		return ret;
	return 1;
}

static int validate_root_item(struct btrfs_fs_info *fs_info,
			      struct extent_buffer *parent,
			      struct extent_buffer *eb, int slot)
{
	struct btrfs_root_item *ri;
	struct btrfs_key key;
	int ret;

	btrfs_item_key_to_cpu(parent, &key, slot);
	ri = btrfs_item_ptr(parent, slot, struct btrfs_root_item);
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
	set_extent_dirty(fs_info->excluded_extents, eb->start,
			 eb->start + fs_info->nodesize - 1);
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
	struct extent_io_tree *tree = fs_info->excluded_extents;
	struct extent_buffer *tmp;
	u64 end = eb->start + eb->len, bytenr;
	int nritems;
	int ret = 0;
	int i;

	if (test_range_bit(tree, eb->start, end - 1, EXTENT_DIRTY, 0)) {
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

	set_extent_dirty(tree, eb->start, end - 1);

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
			if (test_range_bit(tree, bytenr, end, EXTENT_DIRTY,
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

/*
 * Walks through all of the roots that point to the corrupt block and removes
 * the block pointer for that specific node/leaf.
 */
static int delete_corrupt_record(struct btrfs_fs_info *fs_info,
				 struct corrupt_record *rec)
{
	struct btrfs_trans_handle *trans = NULL;
	struct btrfs_root *root;
	struct btrfs_path path;
	struct btrfs_key key;
	int i, ret = 0;

	for (i = 0; i < rec->nr_roots; i++) {
		key.objectid = rec->roots[i];
		key.type = BTRFS_ROOT_ITEM_KEY;
		key.offset = (u64)-1;

		printf("Deleting link to bytenr %llu in root %llu\n",
		       rec->rec_key.bytenr, rec->roots[i]);

		root = btrfs_read_fs_root(fs_info, &key);
		if (IS_ERR(root)) {
			fprintf(stderr, "Couldn't read root %llu\n",
				key.objectid);
			return PTR_ERR(root);
		}

		trans = btrfs_start_transaction(root, 1);
		if (IS_ERR(trans))
			return PTR_ERR(trans);

		btrfs_init_path(&path);
		path.lowest_level = rec->level;
		ret = btrfs_search_slot(trans, root, &rec->key, &path, -1, 1);
		if (ret < 0) {
			fprintf(stderr,
	"Failed to search trying to delete %llu from root %llu %d\n",
				rec->rec_key.bytenr, key.objectid, ret);
			goto abort;
		}

		if (rec->level) {
			printf("deleting slot %d at level %d bytenr %llu which is %llu\n",
			       path.slots[rec->level], rec->level, path.nodes[rec->level]->start,
			       btrfs_node_blockptr(path.nodes[rec->level], path.slots[rec->level]));
			ret = btrfs_del_ptr(root, &path, rec->level,
					    path.slots[rec->level]);
			if (ret) {
				fprintf(stderr,
		"Couldn't delete pointer to %llu from root %llu\n",
					rec->rec_key.bytenr, key.objectid);
				goto abort;
			}
			btrfs_set_root_used(&root->root_item,
					    btrfs_root_used(&root->root_item) -
					    fs_info->nodesize);
		} else {
			ret = btrfs_del_item(trans, root, &path);
			if (ret) {
				fprintf(stderr,
		"Failed to delete the item in root %llu\n",
					key.objectid);
				goto abort;
			}
		}

		/*
		 * We are specifically not freeing the extent reference here
		 * because the extent tree could be corrupt already, and we
		 * don't want to mess things up worse by modifying the extent
		 * tree.
		 *
		 * In the future it may make sense to process any extent tree
		 * records that need to be deleted first, and then for
		 * everything else go ahead and do the btrfs_free_extent, so at
		 * least we're not making more work for ourselves.  But at this
		 * point I don't want to worry about tripping some other problem
		 * and causing us to bail out here.
		 */
		btrfs_commit_transaction(trans, root);
		btrfs_release_path(&path);
	}
	return 0;
abort:
	btrfs_abort_transaction(trans, ret);
	btrfs_release_path(&path);
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
			ret = delete_corrupt_record(fs_info, rec);
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
int validate_and_repair_tree_structure(struct btrfs_fs_info *fs_info)
{
	int ret;

	fs_info->excluded_extents = malloc(sizeof(struct extent_io_tree));
	if (!fs_info->excluded_extents)
		return -ENOMEM;
	extent_io_tree_init(fs_info->excluded_extents);

	ret = validate_tree_blocks(fs_info, fs_info->chunk_root->node,
				   BTRFS_CHUNK_TREE_OBJECTID);
	if (ret)
		goto out;
	ret = validate_tree_blocks(fs_info, fs_info->tree_root->node,
				   BTRFS_ROOT_TREE_OBJECTID);
	if (ret)
		goto out;

	ret = delete_corrupt_records(fs_info);
	if (!ret)
		ret = reinit_broken_roots(fs_info);
out:
	cleanup_excluded_extents();
	return ret;
}
