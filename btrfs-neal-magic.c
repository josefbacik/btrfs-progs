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

int main(int argc, char **argv)
{
	char sb_buf[BTRFS_SUPER_INFO_SIZE];
	u8 result[BTRFS_CSUM_SIZE];
	struct btrfs_super_block *sb;
	ssize_t ret;
	int fd;
	u64 gen, bytenr;
	u16 csum_type;

	if (argc < 4) {
		printf("usage: btrfs-neal-magic <dev> <bytenr> <gen>\n");
		return -1;
	}

	errno = 0;
	bytenr = strtoll(argv[2], NULL, 0);
	if (errno) {
		printf("Invalid number for bytenr\n");
		return -1;
	}

	gen = strtoll(argv[3], NULL, 0);
	if (errno) {
		printf("Invalid number for gen\n");
		return -1;
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		printf("Couldn't open device\n");
		return -1;
	}

	ret = pread(fd, sb_buf, BTRFS_SUPER_INFO_SIZE, btrfs_sb_offset(0));
	if (ret != BTRFS_SUPER_INFO_SIZE) {
		printf("Couldn't read super block\n");
		return -1;
	}

	sb = (struct btrfs_super_block *)sb_buf;
	csum_type = btrfs_super_csum_type(sb);
	btrfs_set_super_generation(sb, gen);
	btrfs_set_super_root(sb, bytenr);
	btrfs_csum_data(csum_type, (u8 *)sb + BTRFS_CSUM_SIZE, result,
			BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE);
	memcpy(&sb->csum[0], result, BTRFS_CSUM_SIZE);

	ret = pwrite(fd, sb_buf, BTRFS_SUPER_INFO_SIZE, btrfs_sb_offset(0));
	if (ret != BTRFS_SUPER_INFO_SIZE) {
		printf("Failed to do our write!!\n");
		return -1;
	}
	fsync(fd);
	close(fd);
	return 0;
}
