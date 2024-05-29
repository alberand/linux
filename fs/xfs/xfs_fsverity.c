/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 Red Hat, Inc.
 */
#include "xfs_platform.h"
#include "xfs_format.h"
#include "xfs_shared.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_fsverity.h"
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include "xfs_inode.h"
#include "xfs_log_format.h"
#include "xfs_bmap_util.h"
#include "xfs_log_format.h"
#include "xfs_trans.h"
#include "xfs_trace.h"
#include "xfs_quota.h"
#include "xfs_fsverity.h"
#include "xfs_iomap.h"
#include "xfs_error.h"
#include "xfs_health.h"
#include <linux/fsverity.h>
#include <linux/iomap.h>
#include <linux/pagemap.h>

loff_t
xfs_fsverity_metadata_offset(
	const struct xfs_inode	*ip)
{
	return round_up(i_size_read(VFS_IC(ip)), XFS_FSVERITY_START_ALIGN);
}

bool
xfs_fsverity_is_file_data(
	const struct xfs_inode	*ip,
	loff_t			offset)
{
	return fsverity_active(VFS_IC(ip)) &&
			offset < xfs_fsverity_metadata_offset(ip);
}

/*
 * Retrieve the verity descriptor.
 */
static int
xfs_fsverity_get_descriptor(
	struct inode		*inode,
	void			*buf,
	size_t			buf_size)
{
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	__be32			d_desc_size;
	u32			desc_size;
	u64			desc_size_pos;
	int			error;
	u64			desc_pos;
	struct xfs_bmbt_irec	rec;
	int			is_empty;
	uint32_t		blocksize = i_blocksize(VFS_I(ip));
	xfs_fileoff_t		last_block_offset;

	ASSERT(inode->i_flags & S_VERITY);
	error = xfs_bmap_last_extent(NULL, ip, XFS_DATA_FORK, &rec, &is_empty);
	if (error)
		return error;

	if (is_empty)
		return -ENODATA;

	last_block_offset =
		XFS_FSB_TO_B(mp, rec.br_startoff + rec.br_blockcount);
	if (last_block_offset < xfs_fsverity_metadata_offset(ip))
		return -ENODATA;

	desc_size_pos = last_block_offset - sizeof(__be32);
	error = fsverity_pagecache_read(inode, (char *)&d_desc_size,
			sizeof(d_desc_size), desc_size_pos);
	if (error)
		return error;

	desc_size = be32_to_cpu(d_desc_size);
	if (XFS_IS_CORRUPT(mp, desc_size > FS_VERITY_MAX_DESCRIPTOR_SIZE))
		return -ERANGE;
	if (XFS_IS_CORRUPT(mp, desc_size > desc_size_pos))
		return -ERANGE;

	if (!buf_size)
		return desc_size;

	if (XFS_IS_CORRUPT(mp, desc_size > buf_size))
		return -ERANGE;

	desc_pos = round_down(desc_size_pos - desc_size, blocksize);
	error = fsverity_pagecache_read(inode, buf, desc_size, desc_pos);
	if (error)
		return error;

	return desc_size;
}

static int
xfs_fsverity_write_descriptor(
	struct file		*file,
	const void		*desc,
	u32			desc_size,
	u64			merkle_tree_size)
{
	int			error;
	struct inode		*inode = file_inode(file);
	struct xfs_inode	*ip = XFS_I(inode);
	unsigned int		blksize = ip->i_mount->m_sb.sb_blocksize;
	u64			tree_last_block =
			xfs_fsverity_metadata_offset(ip) + merkle_tree_size;
	u64			desc_pos =
			round_up(tree_last_block, XFS_FSVERITY_START_ALIGN);
	u64			desc_end = desc_pos + desc_size;
	__be32			desc_size_disk = cpu_to_be32(desc_size);
	u64			desc_size_pos =
			round_up(desc_end + sizeof(desc_size_disk), blksize) -
			sizeof(desc_size_disk);

	error = iomap_fsverity_write(file, desc_size_pos, sizeof(__be32),
			(const void *)&desc_size_disk,
			&xfs_buffered_write_iomap_ops,
			&xfs_iomap_write_ops);
	if (error)
		return error;

	return iomap_fsverity_write(file, desc_pos, desc_size, desc,
			&xfs_buffered_write_iomap_ops,
			&xfs_iomap_write_ops);
}

/*
 * Try to remove all the fsverity metadata after a failed enablement.
 */
static int
xfs_fsverity_delete_metadata(
	struct xfs_inode	*ip)
{
	struct xfs_trans	*tp;
	struct xfs_mount	*mp = ip->i_mount;
	int			error;

	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_itruncate, 0, 0, 0, &tp);
	if (error)
		return error;

	xfs_ilock(ip, XFS_ILOCK_EXCL);
	xfs_trans_ijoin(tp, ip, 0);

	/*
	 * We removing post EOF data, no need to update i_size as fsverity
	 * didn't move i_size in the first place
	 */
	error = xfs_itruncate_extents(&tp, ip, XFS_DATA_FORK, XFS_ISIZE(ip));
	if (error)
		goto err_cancel;

	error = xfs_trans_commit(tp);
	xfs_iunlock(ip, XFS_ILOCK_EXCL);

	return error;

err_cancel:
	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	xfs_trans_cancel(tp);
	return error;
}


/*
 * Prepare to enable fsverity by clearing old metadata.
 */
static int
xfs_fsverity_begin_enable(
	struct file		*filp)
{
	struct inode		*inode = file_inode(filp);
	struct xfs_inode	*ip = XFS_I(inode);
	int			error;

	xfs_assert_ilocked(ip, XFS_IOLOCK_EXCL);

	if (IS_DAX(inode))
		return -EINVAL;

	if (inode->i_size > XFS_FSVERITY_LARGEST_FILE)
		return -EFBIG;

	/*
	 * Flush pagecache before building Merkle tree. Inode is locked and no
	 * further writes will happen to the file except fsverity metadata
	 */
	error = filemap_write_and_wait(inode->i_mapping);
	if (error)
		return error;

	if (xfs_iflags_test_and_set(ip, XFS_VERITY_CONSTRUCTION))
		return -EBUSY;

	error = xfs_qm_dqattach(ip);
	if (error)
		return error;

	return xfs_fsverity_delete_metadata(ip);
}

/*
 * Complete (or fail) the process of enabling fsverity.
 */
static int
xfs_fsverity_end_enable(
	struct file		*file,
	const void		*desc,
	size_t			desc_size,
	u64			merkle_tree_size)
{
	struct inode		*inode = file_inode(file);
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp;
	int			error = 0;
	loff_t			range_start = xfs_fsverity_metadata_offset(ip);

	xfs_assert_ilocked(ip, XFS_IOLOCK_EXCL);

	/* fs-verity failed, just cleanup */
	if (desc == NULL) {
		error = xfs_fsverity_delete_metadata(ip);
		goto out;
	}

	error = xfs_fsverity_write_descriptor(file, desc, desc_size,
			merkle_tree_size);
	if (error)
		goto out;

	/*
	 * Wait for Merkle tree get written to disk before setting on-disk inode
	 * flag and clearing XFS_VERITY_CONSTRUCTION
	 */
	error = filemap_write_and_wait_range(inode->i_mapping, range_start,
			LLONG_MAX);
	if (error)
		goto out;

	/*
	 * Proactively drop any delayed allocations in COW fork, the fsverity
	 * files are read-only
	 */
	if (xfs_is_cow_inode(ip))
		xfs_bmap_punch_delalloc_range(ip, XFS_COW_FORK, 0, LLONG_MAX,
				NULL);

	/*
	 * Set fsverity inode flag
	 */
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

		error2 = xfs_fsverity_delete_metadata(ip);
		if (error2)
			xfs_alert(ip->i_mount,
"ino 0x%llx failed to clean up new fsverity metadata, err %d",
					ip->i_ino, error2);
	}

	xfs_iflags_clear(ip, XFS_VERITY_CONSTRUCTION);
	return error;
}

/*
 * Retrieve a merkle tree block.
 */
static struct page *
xfs_fsverity_read_merkle(
	struct inode		*inode,
	pgoff_t			index)
{
	index += xfs_fsverity_metadata_offset(XFS_I(inode)) >> PAGE_SHIFT;

	return generic_read_merkle_tree_page(inode, index);
}

/*
 * Retrieve a merkle tree block.
 */
static void
xfs_fsverity_readahead_merkle_tree(
	struct inode		*inode,
	pgoff_t			index,
	unsigned long		nr_pages)
{
	index += xfs_fsverity_metadata_offset(XFS_I(inode)) >> PAGE_SHIFT;

	generic_readahead_merkle_tree(inode, index, nr_pages);
}

/*
 * Write a merkle tree block.
 */
static int
xfs_fsverity_write_merkle(
	struct file		*file,
	const void		*buf,
	u64			pos,
	unsigned int		size,
	const u8		*zero_digest,
	unsigned int		digest_size)
{
	struct inode		*inode = file_inode(file);
	struct xfs_inode	*ip = XFS_I(inode);
	loff_t			position = pos +
		xfs_fsverity_metadata_offset(ip);

	if (position + size > inode->i_sb->s_maxbytes)
		return -EFBIG;

	/*
	 * If this is a block full of hashes of zeroed blocks, don't bother
	 * storing the block. We can synthesize them later.
	 *
	 * However, do this only in case Merkle tree block == fs block size.
	 * Iomap synthesizes these blocks based on holes in the merkle tree. We
	 * won't be able to tell if something need to be synthesizes for the
	 * range in the fs block. For example, for 4k filesystem block
	 *
	 *	[ 1k | zero hashes | zero hashes | 1k ]
	 *
	 * Iomap won't know about these empty blocks.
	 */
	if (size == ip->i_mount->m_sb.sb_blocksize &&
			/*
			 * First digest is zero_digest
			 */
			memcmp(buf, zero_digest, digest_size) == 0 &&
			/*
			 * Every digest is same as previous, thus all are
			 * zero_digest
			 */
			memcmp(buf + digest_size, buf, size - digest_size) == 0)
		return 0;

	return iomap_fsverity_write(file, position, size, buf,
			&xfs_buffered_write_iomap_ops,
			&xfs_iomap_write_ops);
}

const struct fsverity_operations xfs_fsverity_ops = {
	.begin_enable_verity		= xfs_fsverity_begin_enable,
	.end_enable_verity		= xfs_fsverity_end_enable,
	.get_verity_descriptor		= xfs_fsverity_get_descriptor,
	.read_merkle_tree_page		= xfs_fsverity_read_merkle,
	.readahead_merkle_tree		= xfs_fsverity_readahead_merkle_tree,
	.write_merkle_tree_block	= xfs_fsverity_write_merkle,
};
