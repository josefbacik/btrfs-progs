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
#include "kernel-shared/print-tree.h"

#define BLOCKSIZE 16384

static void broken_print_tree(struct extent_buffer *eb, int fd)
{
	struct extent_buffer *tmp;
	ssize_t ret;
	int i, nr = btrfs_header_nritems(eb);

	tmp = alloc_dummy_extent_buffer(NULL, 0, BLOCKSIZE);

	btrfs_print_tree(eb, false, 0);
	if (btrfs_header_level(eb) == 0)
		return;

	for (i = 0; i < nr; i++) {
		u64 blocknr = btrfs_node_blockptr(eb, i);

		ret = pread(fd, tmp->data, BLOCKSIZE, blocknr);
		if (ret != BLOCKSIZE) {
			printf("Failed to read bytenr %llu\n", blocknr);
			return;
		}
		broken_print_tree(eb, fd);
	}
	free_extent_buffer(tmp);
}

int main(int argc, char **argv)
{
	struct extent_buffer *eb;
	ssize_t ret;
	u64 bytenr;
	int fd;

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

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		printf("Couldn't open device\n");
		return -1;
	}

	eb = alloc_dummy_extent_buffer(NULL, bytenr, BLOCKSIZE);
	ret = pread(fd, eb->data, BLOCKSIZE, bytenr);
	if (ret != BLOCKSIZE) {
		printf("Failed to read\n");
		return -1;
	}
	broken_print_tree(eb, fd);
	close(fd);
	free_extent_buffer(eb);
	return 0;
}
