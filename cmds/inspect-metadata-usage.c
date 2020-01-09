#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <getopt.h>

#include "kerncompat.h"
#include "ioctl.h"
#include "common/utils.h"
#include "ctree.h"
#include "cmds/commands.h"
#include "common/help.h"

static struct rb_root seen = RB_ROOT;
static unsigned pretty_mode = UNITS_HUMAN;
static u64 max_depth = (u64)-1;
static bool short_print = false;

struct tree_entry {
	struct rb_node n;
	u64 ino;
};

struct inode_entry {
	struct list_head list;
	u64 ino;
	u64 total_bytes;
	u64 inode_item_bytes;
	u64 dir_item_bytes;
	u64 dir_index_bytes;
	u64 inline_bytes;
	u64 extent_item_bytes;
	u64 xattr_bytes;
	u64 inode_ref_bytes;
	u64 inode_extref_bytes;
	char path[PATH_MAX];
};

#define buf_entry(ptr, type) ({							\
	(type *)( (char *)ptr + sizeof(struct btrfs_ioctl_search_header));})

#define PRINT_VALUE(__item, __name)						\
	printf("   %s: %s\n", #__name,						\
	       pretty_size_mode(__item->__name, pretty_mode))

static struct tree_entry *lookup_entry(struct rb_root *root, u64 ino)
{
	struct rb_node *n = root->rb_node;
	struct tree_entry *entry;

	while (n) {
		entry = rb_entry(n, struct tree_entry, n);
		if (ino < entry->ino)
			n = n->rb_left;
		else if (ino > entry->ino)
			n = n->rb_right;
		else
			return entry;
	}
	return NULL;
}

static void insert_entry(struct rb_root *root, struct tree_entry *entry)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct tree_entry *tmp;

	while (*p) {
		parent = *p;
		tmp = rb_entry(parent, struct tree_entry, n);
		if (entry->ino < tmp->ino)
			p = &parent->rb_left;
		else if (entry->ino > tmp->ino)
			p = &parent->rb_right;
		else {
			printf("FUCK\n");
			exit(1);
		}
	}
	rb_link_node(&entry->n, parent, p);
	rb_insert_color(&entry->n, root);
}

static struct inode_entry *add_inode_entry(u64 ino)
{
	struct tree_entry *entry = lookup_entry(&seen, ino);
	struct inode_entry *ie;

	if (entry)
		return NULL;
	entry = calloc(1, sizeof(struct tree_entry));
	ie = calloc(1, sizeof(struct inode_entry));
	if (!entry || !ie) {
		free(ie);
		free(entry);
		return NULL;
	}
	ie->ino = ino;
	entry->ino = ino;
	insert_entry(&seen, entry);
	return ie;
}

static void process_dir_index_item(struct list_head *pending,
				   struct inode_entry *entry,
				   struct btrfs_ioctl_search_header *item)
{
	struct btrfs_dir_item *di = buf_entry(item, struct btrfs_dir_item);
	struct inode_entry *ie;
	struct btrfs_disk_key key;
	char name[PATH_MAX];
	char *name_ptr;

	entry->dir_index_bytes += item->len;
	memcpy(&key, &di->location, sizeof(struct btrfs_disk_key));
	if (btrfs_disk_key_type(&key) != BTRFS_INODE_ITEM_KEY)
		return;
	ie = add_inode_entry(btrfs_disk_key_objectid(&key));
	if (!ie)
		return;
	list_add_tail(&ie->list, pending);
	name_ptr = (char *)(di + 1);
	memcpy(name, name_ptr, btrfs_stack_dir_name_len(di));
	name[btrfs_stack_dir_name_len(di)] = '\0';
	snprintf(ie->path, PATH_MAX, "%s/%s", entry->path, name);
}

static void process_extent_data(struct inode_entry *entry,
				struct btrfs_ioctl_search_header *item)
{
	struct btrfs_file_extent_item *fi = buf_entry(item,
					struct btrfs_file_extent_item);
	entry->extent_item_bytes += sizeof(struct btrfs_file_extent_item);
	if (btrfs_stack_file_extent_type(fi) == BTRFS_FILE_EXTENT_INLINE)
		entry->inline_bytes += item->len -
			offsetof(struct btrfs_file_extent_item, disk_bytenr);
}

static void process_buf(struct list_head *pending,
			struct inode_entry *entry,
			struct btrfs_ioctl_search_args_v2 *args,
			struct btrfs_ioctl_search_key *sk)
{
	struct btrfs_ioctl_search_header *item;
	u32 cur = 0;

	item = (struct btrfs_ioctl_search_header *)args->buf;
	while (cur < sk->nr_items) {
		switch (item->type) {
		case BTRFS_INODE_ITEM_KEY:
			entry->inode_item_bytes += item->len;
			break;
		case BTRFS_INODE_REF_KEY:
			entry->inode_ref_bytes += item->len;
			break;
		case BTRFS_INODE_EXTREF_KEY:
			entry->inode_extref_bytes += item->len;
			break;
		case BTRFS_XATTR_ITEM_KEY:
			entry->xattr_bytes += item->len;
			break;
		case BTRFS_DIR_ITEM_KEY:
			entry->dir_item_bytes += item->len;
			break;
		case BTRFS_DIR_INDEX_KEY:
			process_dir_index_item(pending, entry, item);
			break;
		case BTRFS_EXTENT_DATA_KEY:
			process_extent_data(entry, item);
			break;
		default:
			break;
		}
		sk->min_type = item->type;
		sk->min_offset = item->offset + 1;
		entry->total_bytes += item->len;
		cur++;
		item = (struct btrfs_ioctl_search_header *)
			((char *)item +
			 sizeof(struct btrfs_ioctl_search_header) +
			 item->len);
	}
}

static int stat_file(int fd, struct btrfs_ioctl_search_args_v2 *args,
		     struct inode_entry *parent, struct inode_entry *entry,
		     u64 depth)
{
	struct btrfs_ioctl_search_key *sk;
	LIST_HEAD(pending);
	int ret;

	sk = &(args->key);
	memset(sk, 0, sizeof(struct btrfs_ioctl_search_key));
	sk->max_type = (u32)-1;
	sk->max_offset = (u64)-1;
	sk->max_transid = (u64)-1;
	sk->nr_items = (u32)-1;
	sk->min_objectid = entry->ino;
	sk->max_objectid = entry->ino;

	while (sk->nr_items > 0) {
		sk->nr_items = (u32)-1;
		ret = ioctl(fd, BTRFS_IOC_TREE_SEARCH_V2, args);
		if (ret < 0) {
			error("search failed %d", errno);
			return ret;
		}
		process_buf(&pending, entry, args, sk);
	}

	while (!list_empty(&pending)) {
		struct inode_entry *ie = list_first_entry(&pending,
							  struct inode_entry,
							  list);
		list_del_init(&ie->list);
		ret = stat_file(fd, args, entry, ie, depth + 1);
		if (ret)
			return ret;
		entry->total_bytes += ie->total_bytes;
		entry->inode_item_bytes += ie->inode_item_bytes;
		entry->dir_item_bytes += ie->dir_item_bytes;
		entry->dir_index_bytes += ie->dir_index_bytes;
		entry->inline_bytes += ie->inline_bytes;
		entry->extent_item_bytes += ie->extent_item_bytes;
		entry->xattr_bytes += ie->xattr_bytes;
		entry->inode_ref_bytes += ie->inode_ref_bytes;
		entry->inode_extref_bytes += ie->inode_extref_bytes;
		free(ie);
	}

	if (!short_print && depth <= max_depth) {
		printf("%s\n", entry->path);
		PRINT_VALUE(entry, total_bytes);
		PRINT_VALUE(entry, inode_item_bytes);
		PRINT_VALUE(entry, dir_item_bytes);
		PRINT_VALUE(entry, dir_index_bytes);
		PRINT_VALUE(entry, inline_bytes);
		PRINT_VALUE(entry, extent_item_bytes);
		PRINT_VALUE(entry, xattr_bytes);
		PRINT_VALUE(entry, inode_ref_bytes);
		PRINT_VALUE(entry, inode_extref_bytes);
	} else if (depth <= max_depth) {
		printf("%s\t\t%s\n",
		       pretty_size_mode(entry->total_bytes, pretty_mode),
		       entry->path);
	}

	return 0;
}

static const char * const cmd_inspect_metadata_usage_usage[] = {
	"btrfs inspect-internal metadata-usage <directory>",
	"Print a dump of the metadata usage of the given subvolume",
	"",
	"-b|--bytes		print with bytes instead of pretty sizes",
	"-d|--max-depth		only print out to the given depth",
	"-s|--short		only print the total size, not the details",
	NULL,
};

static const struct option long_options[] = {
	{"bytes", no_argument, NULL, 'b'},
	{"max-depth", required_argument, NULL, 'd'},
	{NULL, 0, NULL, 0}
};
static int cmd_inspect_metadata_usage(const struct cmd_struct *cmd, int argc,
				      char **argv)
{
	struct btrfs_ioctl_search_args_v2 *args;
	struct inode_entry ie = {};
	struct stat st;
	char *buf;
	DIR *dirstream = NULL;
	int fd;
	int opt;

	optind = 0;
	while ((opt = getopt_long(argc, argv, "bd:s", long_options, NULL))
	       != -1) {
		switch(opt) {
		case 'b':
			pretty_mode = UNITS_BYTES;
			break;
		case 'd':
			max_depth = arg_strtou64(optarg);
			break;
		case 's':
			short_print = true;
			break;
		default:
			usage_unknown_option(cmd, argv);
		}
	}

	if (check_argc_exact(argc - optind, 1))
		return 1;

	fd = btrfs_open_dir(argv[optind], &dirstream, 1);
	if (fd < 0)
		return 1;

	if (btrfs_tree_search2_ioctl_supported(fd) != 1) {
		close_file_or_dir(fd, dirstream);
		error("search2 ioctl not supported on this kernel");
		return 1;
	}

	if (fstat(fd, &st)) {
		close_file_or_dir(fd, dirstream);
		error("fstat failed");
		return 1;
	}

	buf = calloc(1, SZ_1M);
	if (!buf) {
		close_file_or_dir(fd, dirstream);
		error("failed to allocate search buffer");
		return 1;
	}

	args = (struct btrfs_ioctl_search_args_v2 *)buf;
	args->buf_size = SZ_1M - sizeof(struct btrfs_ioctl_search_args_v2);
	ie.ino = st.st_ino;
	strcpy(ie.path, argv[optind]);
	if (ie.path[strlen(ie.path) - 1] == '/')
		ie.path[strlen(ie.path) - 1] = '\0';
	stat_file(fd, args, NULL, &ie, 0);

	free(buf);
	close_file_or_dir(fd, dirstream);
	return 0;
}

DEFINE_SIMPLE_COMMAND(inspect_metadata_usage, "metadata-usage");
