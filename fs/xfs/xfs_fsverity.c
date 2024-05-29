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
#include "xfs_format.h"
#include <linux/fsverity.h>
#include <linux/iomap.h>

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
inline void
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
	args->region_offset = XFS_FSVERITY_MTREE_OFFSET;
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

	error = filemap_write_and_wait(inode->i_mapping);
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
	struct xfs_merkle_key	name;
	struct xfs_da_args	args = { };

	pos = pos & XFS_FSVERITY_MTREE_MASK;
	xfs_fsverity_init_merkle_args(ip, &name, pos, &args);

	return xfs_attr_read_iomap(&args, iomap);
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
	struct xfs_da_args	args;
	struct xfs_merkle_key	name;
	loff_t			xattr_name;
	unsigned int		xattr_size;
	int			error;

	if (xfs_is_shutdown(mp))
		return -EIO;

	pos = pos & XFS_FSVERITY_MTREE_MASK;

	/* We always allocate one xattr block, as this block will be used by
	 * iomap. Even for smallest Merkle trees */
	/* TODO this can be optimized to use shortname attributes */
	xattr_size = mp->m_attr_geo->blksize;
	xattr_name = pos & ~(xattr_size - 1);

	xfs_fsverity_init_merkle_args(ip, &name, xattr_name, &args);
	args.valuelen = xattr_size;
	args.region_offset = XFS_FSVERITY_MTREE_OFFSET;

	error = xfs_attr_write_iomap(&args, iomap);
	if (error)
		return error;

	/* Offset into xattr block. One block can have multiple merkle tree
	 * blocks */
	iomap->offset += (pos & (xattr_size - 1));
	/* Instead of attribute size (which blksize) use requested
	 * size */
	iomap->length = length;

	return 0;
}

int
xfs_fsverity_end_ioend(
	struct xfs_inode	*ip,
	struct iomap_ioend	*ioend)
{
	struct xfs_da_args	args;
	struct xfs_merkle_key	name;
	loff_t			pos;
	struct bio		bio = ioend->io_bio;
	void			*addr;
	int			error;
	struct folio		*folio = bio_first_folio_all(&bio);

	pos = ioend->io_offset & XFS_FSVERITY_MTREE_MASK;
	xfs_fsverity_init_merkle_args(ip, &name, pos, &args);
	args.valuelen = ioend->io_size;
	addr = kmap_local_folio(folio, 0);
	args.value = addr;
	error = xfs_attr_write_end_ioend(&args);
	kunmap_local(addr);

	return error;
}

const struct iomap_ops xfs_fsverity_write_iomap_ops = {
	.iomap_begin = xfs_fsverity_write_iomap_begin,
};

void
xfs_attr_verify_args(
		struct work_struct	*work)
{
	struct xfs_inode		*ip;
	void				*addr;
	struct xfs_merkle_key		name;
	struct xfs_da_args		args;
	int				error;
	struct iomap_read_ioend		*ioend =
		container_of(work, struct iomap_read_ioend, io_work);
	struct bio			*bio = &ioend->io_bio;
	struct folio			*folio = bio_first_folio_all(bio);

	ip = XFS_I(ioend->io_inode);
	xfs_fsverity_init_merkle_args(ip, &name, ioend->io_offset, &args);
	addr = kmap_local_folio(folio, 0);
	args.valuelen = ioend->io_size;
	args.value = addr;
	error = xfs_attr_read_end_io(&args);
	kunmap_local(addr);
	if (error)
		bio->bi_status = BLK_STS_IOERR;
	iomap_read_end_io(bio);
}

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
	int		error;
	u8		log_blocksize;

	error = fsverity_merkle_tree_geometry(inode, &log_blocksize, &block_size,
				      &tree_size);
	if (error)
		return ERR_PTR(error);

	struct ioregion region = {
		.inode = inode,
		.pos = index << log_blocksize,
		.length = block_size,
		.offset = XFS_FSVERITY_MTREE_OFFSET,
		.ops = &xfs_fsverity_read_iomap_ops,
	};

	folio = iomap_read_region(&region);
	if (IS_ERR(folio))
		return ERR_CAST(folio);

	/* Wait for buffered read to finish */
	error = folio_wait_locked_killable(folio);
	if (error)
		return ERR_PTR(error);
	if (IS_ERR(folio) || !folio_test_uptodate(folio))
		return ERR_PTR(-EFSCORRUPTED);

	return folio_file_page(folio, 0);
}

/* Write a merkle tree block. */
static int
xfs_fsverity_write_merkle(
	struct inode	*inode,
	const void	*buf,
	u64		pos,
	unsigned int	size)
{
	struct ioregion region = {
		.inode = inode,
		.pos = pos,
		.buf = buf,
		.length = size,
		.offset = XFS_FSVERITY_MTREE_OFFSET,
		.ops = &xfs_fsverity_write_iomap_ops,
	};

	return iomap_write_region(&region);
}

const struct fsverity_operations xfs_fsverity_ops = {
	.begin_enable_verity		= xfs_fsverity_begin_enable,
	.end_enable_verity		= xfs_fsverity_end_enable,
	.get_verity_descriptor		= xfs_fsverity_get_descriptor,
	.read_merkle_tree_page		= xfs_fsverity_read_merkle,
	.write_merkle_tree_block	= xfs_fsverity_write_merkle,
};
