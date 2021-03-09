#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include "kerncompat.h"
#include "kernel-shared/ctree.h"
#include "kernel-shared/disk-io.h"
#include "kernel-shared/volumes.h"
#include "kernel-shared/print-tree.h"

#define BLOCKSIZE 16384

static void broken_print_tree(struct btrfs_fs_info *fs_info,
			      struct extent_buffer *eb)
{
	struct extent_buffer *tmp;
	int i, nr = btrfs_header_nritems(eb);

	btrfs_print_tree(eb, false, 0);
	if (btrfs_header_level(eb) == 0)
		return;

	for (i = 0; i < nr; i++) {
		u64 blocknr = btrfs_node_blockptr(eb, i);

		tmp = read_tree_block(fs_info, blocknr, 0);
		if (!tmp || IS_ERR(tmp)) {
			printf("Failed to read bytenr %llu\n", blocknr);
			return;
		}
		broken_print_tree(fs_info, tmp);
		free_extent_buffer(tmp);
	}
}

int main(int argc, char **argv)
{
	struct btrfs_fs_info *fs_info;
	struct extent_buffer *eb;
	u64 bytenr;

	if (argc < 3) {
		printf("usage: btrfs-pring-block <dev> <bytenr>\n");
		return -1;
	}

	errno = 0;
	bytenr = strtoll(argv[2], NULL, 0);
	if (errno) {
		printf("Invalid number for bytenr\n");
		return -1;
	}

	fs_info = open_ctree_fs_info(argv[1], 0, 0, 0,
				     OPEN_CTREE_CHUNK_ROOT_ONLY |
				     OPEN_CTREE_IGNORE_CHUNK_TREE_ERROR);
	if (!fs_info) {
		printf("open ctree failed\n");
		return -1;
	}

	eb = read_tree_block(fs_info, bytenr, 0);
	if (!eb || IS_ERR(eb)) {
		printf("Failed to do initial read\n");
		return -1;
	}
	broken_print_tree(fs_info, eb);
	free_extent_buffer(eb);

	close_ctree_fs_info(fs_info);
	btrfs_close_all_devices();
	return 0;
}
