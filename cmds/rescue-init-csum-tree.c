/* SPDX-License-Identifier: GPL-2.0 */

#include "kerncompat.h"
#include "common/messages.h"
#include "kernel-shared/ctree.h"
#include "kernel-shared/disk-io.h"
#include "kernel-shared/volumes.h"
#include "kernel-shared/transaction.h"

typedef int (root_cb_t)(struct btrfs_root *root, u64 *processed);
static struct extent_io_tree inserted;
static char *data_buf = NULL;
static u64 data_bytes;

static struct btrfs_space_info *__find_space_info(struct btrfs_fs_info *info,
						  u64 flags)
{
	struct btrfs_space_info *found;

	flags &= BTRFS_BLOCK_GROUP_TYPE_MASK;

	list_for_each_entry(found, &info->space_info, list) {
		if (found->flags & flags)
			return found;
	}
	return NULL;

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

static int populate_csum(struct extent_buffer *eb, int slot)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *csum_root;
	struct btrfs_file_extent_item *fi;
	u64 bytenr, num_bytes, offset = 0;
	int ret;
	u8 type;

	fi = btrfs_item_ptr(eb, slot, struct btrfs_file_extent_item);
	bytenr = btrfs_file_extent_disk_bytenr(eb, fi);
	num_bytes = btrfs_file_extent_disk_num_bytes(eb, fi);
	type = btrfs_file_extent_type(eb, fi);

	csum_root = btrfs_csum_root(eb->fs_info, bytenr);
	trans = btrfs_start_transaction(csum_root, 0);
	if (IS_ERR(trans)) {
		error("couldn't start trans handle");
		return PTR_ERR(trans);
	}

	while (offset < num_bytes) {
		u64 sectorsize = eb->fs_info->sectorsize;
		ret = read_extent_data(eb->fs_info, data_buf, bytenr + offset,
				       &sectorsize, 0);
		if (ret) {
			error("couldn't read data bytenr %llu",
			      bytenr + offset);
			return ret;
		}
		ret = btrfs_csum_file_block(trans, bytenr + num_bytes,
					    bytenr + offset, data_buf,
					    sectorsize);
		if (ret) {
			error("couldn't csum the files blocks");
			return ret;
		}
		offset += sectorsize;
	}

	if (type == BTRFS_FILE_EXTENT_PREALLOC) {
		bytenr += btrfs_file_extent_offset(eb, fi);
		num_bytes = btrfs_file_extent_num_bytes(eb, fi);
		ret = btrfs_del_csums(trans, bytenr, num_bytes);
		if (ret < 0) {
			error("failed to trim unwanted csums");
			return ret;
		}
	}

	ret = btrfs_commit_transaction(trans, csum_root);
	if (ret)
		error("failed to commit transaction %d", ret);
	return ret;
}

static int record_csums_eb(struct extent_buffer *eb, u64 *processed)
{
	struct btrfs_file_extent_item *fi;
	struct btrfs_key key;
	u64 bytenr, num_bytes, skip_ino = (u64)-1;
	int ret = 0;
	int pct;
	int i;
	u8 type;

	set_extent_dirty(&inserted, eb->start, eb->start + eb->len - 1);

	for (i = 0; i < btrfs_header_nritems(eb); i++) {
		if (btrfs_header_level(eb) != 0) {
			struct extent_buffer *tmp;
			u64 gen = btrfs_node_ptr_generation(eb, i);

			bytenr = btrfs_node_blockptr(eb, i);

			/* Don't walk down nodes already processed. */
			if (test_range_bit(&inserted, bytenr,
					   bytenr + eb->len - 1,
					   EXTENT_DIRTY, 0))
				continue;

			tmp = read_tree_block(eb->fs_info, bytenr, gen);
			if (IS_ERR(tmp)) {
				error("couldn't read tree block, please run btrfs rescue tree-recover");
				return PTR_ERR(tmp);
			}

			ret = record_csums_eb(tmp, processed);
			free_extent_buffer_nocache(tmp);
			if (ret)
				return ret;
			continue;
		}

		btrfs_item_key_to_cpu(eb, &key, i);
		if (key.type != BTRFS_EXTENT_DATA_KEY &&
		    key.type != BTRFS_INODE_ITEM_KEY)
			continue;

		if (key.objectid == skip_ino)
			continue;

		if (key.type == BTRFS_INODE_ITEM_KEY) {
			struct btrfs_inode_item *ii;
			u32 ii_size;

			ii = btrfs_item_ptr(eb, i, struct btrfs_inode_item);
			ii_size = btrfs_item_size_nr(eb, i);
			if (ii_size < sizeof(struct btrfs_inode_item)) {
				fprintf(stderr, "wtf, bad inode item with size of %u\n",
					ii_size);
				return -EINVAL;
			}
			if (btrfs_inode_flags(eb, ii) & BTRFS_INODE_NODATASUM)
				skip_ino = key.objectid;
			continue;
		}

		fi = btrfs_item_ptr(eb, i, struct btrfs_file_extent_item);
		type = btrfs_file_extent_type(eb, fi);
		if (type == BTRFS_FILE_EXTENT_INLINE)
			continue;

		bytenr = btrfs_file_extent_disk_bytenr(eb, fi);
		num_bytes = btrfs_file_extent_disk_num_bytes(eb, fi);
		if (bytenr == 0)
			continue;

		/*
		 * If we have a prealloc extent that coves the entire range of
		 * the original range then we know we didn't punch a hole and we
		 * can just skip the extent altogether.
		 */
		if (type == BTRFS_FILE_EXTENT_PREALLOC &&
		    btrfs_file_extent_offset(eb, fi) == 0 &&
		    btrfs_file_extent_num_bytes(eb, fi) == num_bytes) {
			*processed += num_bytes;
			continue;
		}

		if (test_range_bit(&inserted, bytenr, bytenr + num_bytes - 1,
				   EXTENT_DIRTY, 0))
			continue;

		set_extent_dirty(&inserted, bytenr, bytenr + num_bytes - 1);

		ret = populate_csum(eb, i);
		if (ret)
			break;
		*processed += num_bytes;
	}

	pct = (int)((*processed * 100ULL) / data_bytes);

	printf("\rprocessed %llu of %llu possible data bytes, %d%%",
	       *processed, data_bytes, pct);
	fflush(stdout);

	return ret;
}

static int record_csums(struct btrfs_root *root, u64 *processed)
{
	return record_csums_eb(root->node, processed);
}

static int foreach_root(struct btrfs_fs_info *fs_info,
			root_cb_t cb)
{
	struct btrfs_root *root;
	struct btrfs_key key = { .type = BTRFS_ROOT_ITEM_KEY };
	struct btrfs_path path;
	u64 processed = 0;
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

		ret = cb(root, &processed);
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

int btrfs_init_csum_tree(const char *path)
{
	struct btrfs_fs_info *fs_info;
	struct btrfs_space_info *space_info;
	struct btrfs_trans_handle *trans;
	struct open_ctree_flags ocf = {};
	int ret = 0;

	ocf.filename = path;
	ocf.flags = OPEN_CTREE_WRITES;

	fs_info = open_ctree_fs_info(&ocf);
	if (!fs_info) {
		error("open ctree failed, try btrfs rescue tree-recover");
		return -1;
	}

	fs_info->suppress_check_block_errors = 1;

	space_info = __find_space_info(fs_info, BTRFS_BLOCK_GROUP_DATA);
	data_bytes = space_info->bytes_used;

	extent_io_tree_init(&inserted);

	data_buf = calloc(1, fs_info->sectorsize);
	if (!data_buf) {
		error("couldn't allocate data buffer");
		goto out;
	}

	trans = btrfs_start_transaction(fs_info->tree_root, 0);
	if (IS_ERR(trans)) {
		error("couldn't start trans handle");
		ret = PTR_ERR(trans);
		goto out;
	}

	ret = reinit_global_roots(trans, BTRFS_CSUM_TREE_OBJECTID);
	if (ret) {
		error("csum root initialization failed");
		goto out;
	}

	ret = btrfs_commit_transaction(trans, fs_info->tree_root);
	if (ret) {
		error("couldn't commit transaction");
		goto out;
	}

	ret = foreach_root(fs_info, record_csums);
out:
	if (data_buf)
		free(data_buf);
	extent_io_tree_cleanup(&inserted);
	printf("doing close???\n");
	close_ctree_fs_info(fs_info);
	return ret;
}
