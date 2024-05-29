/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Red Hat, Inc.
 */
#include "xfs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_log_format.h"
#include "xfs_attr.h"
#include "xfs_verity.h"
#include "xfs_bmap_util.h"
#include "xfs_log_format.h"
#include "xfs_trans.h"
#include "xfs_attr_leaf.h"
#include "xfs_trace.h"
#include "xfs_quota.h"
#include "xfs_ag.h"
#include "xfs_fsverity.h"
#include "xfs_iomap.h"
#include "xfs_bmap.h"
#include "xfs_health.h"
#include <linux/fsverity.h>

/*
 * Initialize an args structure to load or store the fsverity descriptor.
 * Caller must ensure @args is zeroed except for value and valuelen.
 */
static inline void
xfs_fsverity_init_vdesc_args(
	struct xfs_inode	*ip,
	struct xfs_da_args	*args)
{
	args->geo = ip->i_mount->m_attr_geo;
	args->whichfork = XFS_ATTR_FORK,
	args->attr_filter = XFS_ATTR_VERITY;
	args->op_flags = XFS_DA_OP_OKNOENT;
	args->dp = ip;
	args->owner = ip->i_ino;
	args->name = XFS_VERITY_DESCRIPTOR_NAME;
	args->namelen = XFS_VERITY_DESCRIPTOR_NAME_LEN;
	xfs_attr_sethash(args);
}

/*
 * Initialize an args structure to load or store a merkle tree block.
 * Caller must ensure @args is zeroed except for value and valuelen.
 */
static inline void
xfs_fsverity_init_merkle_args(
	struct xfs_inode	*ip,
	struct xfs_merkle_key	*key,
	uint64_t		merkleoff,
	struct xfs_da_args	*args)
{
	xfs_merkle_key_to_disk(key, merkleoff);
	args->geo = ip->i_mount->m_attr_geo;
	args->whichfork = XFS_ATTR_FORK,
	args->attr_filter = XFS_ATTR_VERITY;
	args->op_flags = XFS_DA_OP_OKNOENT;
	args->dp = ip;
	args->owner = ip->i_ino;
	args->name = (const uint8_t *)key;
	args->namelen = sizeof(struct xfs_merkle_key);
	xfs_attr_sethash(args);
}

/* Delete the verity descriptor. */
static int
xfs_fsverity_delete_descriptor(
	struct xfs_inode	*ip)
{
	struct xfs_da_args	args = { };

	xfs_fsverity_init_vdesc_args(ip, &args);
	return xfs_attr_set(&args, XFS_ATTRUPDATE_REMOVE, false);
}

/* Delete a merkle tree block. */
static int
xfs_fsverity_delete_merkle_block(
	struct xfs_inode	*ip,
	u64			pos)
{
	struct xfs_merkle_key	name;
	struct xfs_da_args	args = { };

	xfs_fsverity_init_merkle_args(ip, &name, pos, &args);
	return xfs_attr_set(&args, XFS_ATTRUPDATE_REMOVE, false);
}

/* Retrieve the verity descriptor. */
static int
xfs_fsverity_get_descriptor(
	struct inode		*inode,
	void			*buf,
	size_t			buf_size)
{
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_da_args	args = {
		.value		= buf,
		.valuelen	= buf_size,
	};
	int			error = 0;

	/*
	 * The fact that (returned attribute size) == (provided buf_size) is
	 * checked by xfs_attr_copy_value() (returns -ERANGE).  No descriptor
	 * is treated as a short read so that common fsverity code will
	 * complain.
	 */
	xfs_fsverity_init_vdesc_args(ip, &args);
	error = xfs_attr_get(&args);
	if (error == -ENOATTR)
		return 0;
	if (error)
		return error;

	return args.valuelen;
}

/*
 * Clear out old fsverity metadata before we start building a new one.  This
 * could happen if, say, we crashed while building fsverity data.
 */
static int
xfs_fsverity_delete_stale_metadata(
	struct xfs_inode	*ip,
	u64			new_tree_size,
	unsigned int		tree_blocksize)
{
	u64			pos;
	int			error = 0;

	/*
	 * Delete as many merkle tree blocks in increasing blkno order until we
	 * don't find any more.  That ought to be good enough for avoiding
	 * dead bloat without excessive runtime.
	 */
	for (pos = new_tree_size; !error; pos += tree_blocksize) {
		if (fatal_signal_pending(current))
			return -EINTR;
		error = xfs_fsverity_delete_merkle_block(ip, pos);
		if (error)
			break;
	}

	return error != -ENOATTR ? error : 0;
}

/* Prepare to enable fsverity by clearing old metadata. */
static int
xfs_fsverity_begin_enable(
	struct file		*filp,
	u64			merkle_tree_size,
	unsigned int		tree_blocksize)
{
	struct inode		*inode = file_inode(filp);
	struct xfs_inode	*ip = XFS_I(inode);
	int			error;

	xfs_assert_ilocked(ip, XFS_IOLOCK_EXCL);

	if (IS_DAX(inode))
		return -EINVAL;

	if (xfs_iflags_test_and_set(ip, XFS_VERITY_CONSTRUCTION))
		return -EBUSY;

	error = xfs_qm_dqattach(ip);
	if (error)
		return error;

	return xfs_fsverity_delete_stale_metadata(ip, merkle_tree_size,
			tree_blocksize);
}

/* Try to remove all the fsverity metadata after a failed enablement. */
static int
xfs_fsverity_delete_metadata(
	struct xfs_inode	*ip,
	u64			merkle_tree_size,
	unsigned int		tree_blocksize)
{
	u64			pos;
	int			error;

	if (!merkle_tree_size)
		return 0;

	for (pos = 0; pos < merkle_tree_size; pos += tree_blocksize) {
		if (fatal_signal_pending(current))
			return -EINTR;
		error = xfs_fsverity_delete_merkle_block(ip, pos);
		if (error == -ENOATTR)
			error = 0;
		if (error)
			return error;
	}

	error = xfs_fsverity_delete_descriptor(ip);
	return error != -ENOATTR ? error : 0;
}

/* Complete (or fail) the process of enabling fsverity. */
static int
xfs_fsverity_end_enable(
	struct file		*filp,
	const void		*desc,
	size_t			desc_size,
	u64			merkle_tree_size,
	unsigned int		tree_blocksize)
{
	struct xfs_da_args	args = {
		.value		= (void *)desc,
		.valuelen	= desc_size,
	};
	struct inode		*inode = file_inode(filp);
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp;
	int			error = 0;

	xfs_assert_ilocked(ip, XFS_IOLOCK_EXCL);

	/* fs-verity failed, just cleanup */
	if (desc == NULL)
		goto out;

	xfs_fsverity_init_vdesc_args(ip, &args);
	error = xfs_attr_set(&args, XFS_ATTRUPDATE_UPSERT, false);
	if (error)
		goto out;

	/* Set fsverity inode flag */
	error = xfs_trans_alloc_inode(ip, &M_RES(mp)->tr_ichange,
			0, 0, false, &tp);
	if (error)
		goto out;

	/*
	 * Ensure that we've persisted the verity information before we enable
	 * it on the inode and tell the caller we have sealed the inode.
	 */
	ip->i_diflags2 |= XFS_DIFLAG2_VERITY;

	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
	xfs_trans_set_sync(tp);

	error = xfs_trans_commit(tp);
	xfs_iunlock(ip, XFS_ILOCK_EXCL);

	if (!error)
		inode->i_flags |= S_VERITY;

out:
	if (error) {
		int	error2;

		error2 = xfs_fsverity_delete_metadata(ip,
				merkle_tree_size, tree_blocksize);
		if (error2)
			xfs_alert(ip->i_mount,
 "ino 0x%llx failed to clean up new fsverity metadata, err %d",
					ip->i_ino, error2);
	}

	xfs_iflags_clear(ip, XFS_VERITY_CONSTRUCTION);
	return error;
}

static int
xfs_fsverity_read_iomap_begin(
	struct inode		*inode,
	loff_t			pos,
	loff_t			length,
	unsigned		flags,
	struct iomap		*iomap,
	struct iomap		*srcmap)
{
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_merkle_key	name;
	unsigned int		block_size;
	struct xfs_da_args	args;
	int			error;
	int			mblocks_count;
	struct xfs_bmbt_irec	map[1];
	int			nmap;

	fsverity_merkle_tree_geometry(inode, &block_size, NULL);
	mblocks_count = length / block_size;

	if (xfs_is_shutdown(mp))
		return -EIO;

	xfs_fsverity_init_merkle_args(ip, &name, pos, &args);
	/* We just need to find the attribute and block it's pointing
	 * to. The reading of data would be done by iomap */
	args.valuelen = 0;
	error = xfs_attr_get(&args);
	if (error)
		return error;

	error = xfs_bmapi_read(ip, (xfs_fileoff_t)args.rmtblkno,
			       args.rmtblkcnt, map, &nmap,
			       XFS_BMAPI_ATTRFORK);

	return xfs_bmbt_to_iomap(ip, iomap, map, flags, 0, 0);
}

const struct iomap_ops xfs_fsverity_read_iomap_ops = {
	.iomap_begin = xfs_fsverity_read_iomap_begin,
};

static int
xfs_fsverity_write_iomap_begin(
	struct inode		*inode,
	loff_t			pos,
	loff_t			length,
	unsigned		flags,
	struct iomap		*iomap,
	struct iomap		*srcmap)
{
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	unsigned int		block_size;
	struct xfs_da_args	args;
	unsigned		lockmode;
	int			seq;
	int			error;
	struct xfs_bmbt_irec	map[1];
	int			nmap = 1;

	if (xfs_is_shutdown(mp))
		return -EIO;

	fsverity_merkle_tree_geometry(inode, &block_size, NULL);
	args.valuelen = block_size;
	/* We mimic UNWRITTEN state here over iomap write */
	args.attr_filter |= XFS_ATTR_INCOMPLETE;

	/* TODO                     check vvvvvvvvvvvv */
	error = xfs_attr_set(&args, XFS_ATTRUPDATE_UPSERT, false);
	if (error)
		return error;

	/* TODO check FSB_TO_DADDR/FSB_TO_BB here and in read */
	/* TODO probably I need to think about all those offsets conversions */
	error = xfs_bmapi_read(ip, (xfs_fileoff_t)args.rmtblkno,
			       args.rmtblkcnt, map, &nmap,
			       XFS_BMAPI_ATTRFORK);
	if (error)
		return error;

	/* TODO I probably need locking here */
	lockmode = xfs_ilock_attr_map_shared(ip);
	seq = xfs_iomap_inode_sequence(ip, IOMAP_F_XATTR);
	xfs_iunlock(ip, lockmode);

	if (error)
		return error;
	return xfs_bmbt_to_iomap(ip, iomap, map, flags, IOMAP_F_XATTR, seq);
}

int
xfs_fsverity_end_ioend(
	struct xfs_inode	*ip,
	struct iomap_ioend	*ioend)
{
	struct xfs_da_args	args;
	struct xfs_merkle_key	name;
	xfs_off_t		offset = ioend->io_offset;

	xfs_fsverity_init_merkle_args(ip, &name, offset, &args);
	args.attr_filter &= ~XFS_ATTR_INCOMPLETE;

	/* TODO calculate and save data CRC */
	/* TODO no buffer, no header */

	/* TODO                     check vvvvvvvvvvvv */
	return xfs_attr_set(&args, XFS_ATTRUPDATE_UPSERT, false);
}

const struct iomap_ops xfs_fsverity_write_iomap_ops = {
	.iomap_begin = xfs_fsverity_write_iomap_begin,
};

/* Retrieve a merkle tree block. */
static struct page *
xfs_fsverity_read_merkle(
	struct inode	*inode,
	pgoff_t		index,
	unsigned long	num_ra_pages)
{
	struct folio	*folio;
	unsigned int	block_size;
	u64		tree_size;
	fsverity_merkle_tree_geometry(inode, &block_size, &tree_size);

	folio = iomap_fsverity_read(inode, index, block_size,
			&xfs_fsverity_read_iomap_ops);
	if (IS_ERR(folio))
		return folio_page(folio, 0);

	return folio_page(folio, 0);
}

/* Write a merkle tree block. */
static int
xfs_fsverity_write_merkle(
	struct inode	*inode,
	const void	*buf,
	u64		pos,
	unsigned int	size)
{
	unsigned int	block_size;
	u64		tree_size;
	pgoff_t		offset;
	fsverity_merkle_tree_geometry(inode, &block_size, &tree_size);

	/* TODO better division? */
	offset = pos >> ilog2(block_size);

	return iomap_fsverity_write(inode, buf, offset, size,
			&xfs_fsverity_write_iomap_ops);
}

static void
xfs_fsverity_file_corrupt(
	struct inode		*inode,
	loff_t			pos,
	size_t			len)
{
	xfs_inode_mark_sick(XFS_I(inode), XFS_SICK_INO_DATA);
}

const struct fsverity_operations xfs_fsverity_ops = {
	.begin_enable_verity		= xfs_fsverity_begin_enable,
	.end_enable_verity		= xfs_fsverity_end_enable,
	.get_verity_descriptor		= xfs_fsverity_get_descriptor,
	.read_merkle_tree_page		= xfs_fsverity_read_merkle,
	.write_merkle_tree_block	= xfs_fsverity_write_merkle,
	.file_corrupt			= xfs_fsverity_file_corrupt,
};
