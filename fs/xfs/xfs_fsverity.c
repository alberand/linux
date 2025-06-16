/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */
#include "xfs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
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
#include <linux/pagemap.h>

static int
xfs_fsverity_read(
	struct inode	*inode,
	void		*buf,
	size_t		count,
	loff_t		pos)
{
	struct folio	*folio;
	size_t		n;

	while (count) {
		folio = read_mapping_folio(inode->i_mapping, pos >> PAGE_SHIFT,
					 NULL);
		if (IS_ERR(folio))
			return PTR_ERR(folio);

		n = memcpy_from_file_folio(buf, folio, pos, count);
		folio_put(folio);

		buf += n;
		pos += n;
		count -= n;
	}
	return 0;
}

static int
xfs_fsverity_write(
	struct xfs_inode	*ip,
	loff_t			pos,
	size_t			length,
	const void		*buf)
{
	int			ret;
	ret = iomap_fsverity_write(VFS_I(ip), pos, length, buf,
				   &xfs_buffered_write_iomap_ops,
				   &xfs_iomap_write_ops);
	if (ret < 0)
		return ret;
	return 0;
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
	xfs_fileoff_t		last_block;

	trace_xfs_fsverity_get_descriptor(ip);

	ASSERT(inode->i_flags & S_VERITY);
	error = xfs_bmap_last_extent(NULL, ip, XFS_DATA_FORK, &rec, &is_empty);
	if (error)
		return error;

	if (is_empty)
		return -ENODATA;

	last_block = (rec.br_startoff + rec.br_blockcount);
	desc_size_pos = (last_block << ip->i_mount->m_sb.sb_blocklog) -
			sizeof(__be32);
	error = xfs_fsverity_read(inode, (char *)&d_desc_size,
				  sizeof(d_desc_size), desc_size_pos);
	if (error)
		return error;

	desc_size = be32_to_cpu(d_desc_size);
	if (XFS_IS_CORRUPT(mp, desc_size > FS_VERITY_MAX_DESCRIPTOR_SIZE)) {
		xfs_inode_mark_sick(XFS_I(inode), XFS_SICK_INO_FSVERITY);
		return -ERANGE;
	}

	if (XFS_IS_CORRUPT(mp, desc_size > desc_size_pos)) {
		xfs_inode_mark_sick(XFS_I(inode), XFS_SICK_INO_FSVERITY);
		return -ERANGE;
	}

	if (!buf_size)
		return desc_size;

	if (XFS_IS_CORRUPT(mp, desc_size > buf_size)) {
		xfs_inode_mark_sick(XFS_I(inode), XFS_SICK_INO_FSVERITY);
		return -ERANGE;
	}

	desc_pos = round_down(desc_size_pos - desc_size, blocksize);
	error = xfs_fsverity_read(inode, buf, desc_size, desc_pos);
	if (error)
		return error;

	return desc_size;
}

static int
xfs_fsverity_write_descriptor(
	struct xfs_inode	*ip,
	const void		*desc,
	u32			desc_size,
	u64			merkle_tree_size)
{
	int			error;
	unsigned int		blksize = ip->i_mount->m_attr_geo->blksize;
	u64			desc_pos = round_up(
			XFS_FSVERITY_REGION_START | merkle_tree_size, blksize);
	u64			desc_end = desc_pos + desc_size;
	__be32			desc_size_disk = cpu_to_be32(desc_size);
	u64			desc_size_pos =
			round_up(desc_end + sizeof(desc_size_disk), blksize) -
			sizeof(desc_size_disk);

	error = xfs_fsverity_write(ip, desc_size_pos,
				   sizeof(__be32),
				   (const void *)&desc_size_disk);
	if (error)
		return error;

	error = xfs_fsverity_write(ip, desc_pos, desc_size, desc);

	return error;
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
	if (error)
		goto err_cancel;
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

	if (inode->i_size > XFS_FSVERITY_REGION_START)
		return -EFBIG;

	if (xfs_iflags_test_and_set(ip, XFS_VERITY_CONSTRUCTION))
		return -EBUSY;

	error = xfs_qm_dqattach(ip);
	if (error)
		return error;

	/*
	 * Flush pagecache before building Merkle tree. Inode is locked and no
	 * further writes will happen to the file except fsverity metadata
	 */
	error = filemap_write_and_wait(inode->i_mapping);
	if (error)
		return error;

	return xfs_fsverity_delete_metadata(ip);
}

/*
 * Complete (or fail) the process of enabling fsverity.
 */
static int
xfs_fsverity_end_enable(
	struct file		*filp,
	const void		*desc,
	size_t			desc_size,
	u64			merkle_tree_size)
{
	struct inode		*inode = file_inode(filp);
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp;
	int			error = 0;

	xfs_assert_ilocked(ip, XFS_IOLOCK_EXCL);

	/* fs-verity failed, just cleanup */
	if (desc == NULL)
		goto out;

	error = xfs_fsverity_write_descriptor(ip, desc, desc_size,
					      merkle_tree_size);
	if (error)
		goto out;

	/*
	 * Wait for Merkle tree get written to disk before setting on-disk inode
	 * flag and clearing XFS_VERITY_CONSTRUCTION
	 */
	error = filemap_write_and_wait(inode->i_mapping);
	if (error)
		goto out;

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
	pgoff_t			index,
	unsigned long		num_ra_pages)
{
	struct folio            *folio;
	pgoff_t			offset =
			index | (XFS_FSVERITY_REGION_START >> PAGE_SHIFT);

	trace_xfs_fsverity_read_merkle(XFS_I(inode), offset, PAGE_SIZE);

	folio = __filemap_get_folio(inode->i_mapping, offset, FGP_ACCESSED, 0);
	if (IS_ERR(folio) || !folio_test_uptodate(folio)) {
		DEFINE_READAHEAD(ractl, NULL, NULL, inode->i_mapping, offset);

		if (!IS_ERR(folio))
			folio_put(folio);
		else if (num_ra_pages > 1)
			page_cache_ra_unbounded(&ractl, num_ra_pages, 0);
		folio = read_mapping_folio(inode->i_mapping, offset, NULL);
		if (IS_ERR(folio))
			return ERR_CAST(folio);
	}
	return folio_file_page(folio, offset);
}

/*
 * Write a merkle tree block.
 */
static int
xfs_fsverity_write_merkle(
	struct inode		*inode,
	const void		*buf,
	u64			pos,
	unsigned int		size)
{
	struct xfs_inode	*ip = XFS_I(inode);
	loff_t			position = pos | XFS_FSVERITY_REGION_START;

	trace_xfs_fsverity_write_merkle(XFS_I(inode), pos, size);

	if (position + size > inode->i_sb->s_maxbytes)
		return -EFBIG;

	return xfs_fsverity_write(ip, position, size, buf);
}

static void
xfs_fsverity_file_corrupt(
	struct inode		*inode,
	loff_t			pos,
	size_t			len)
{
	trace_xfs_fsverity_file_corrupt(XFS_I(inode), pos, len);

	xfs_inode_mark_sick(XFS_I(inode), XFS_SICK_INO_DATA);
}

const ptrdiff_t info_offs = (int)offsetof(struct xfs_inode, i_verity_info) -
			    (int)offsetof(struct xfs_inode, i_vnode);

const struct fsverity_operations xfs_fsverity_ops = {
	.inode_info_offs		= info_offs,
	.begin_enable_verity		= xfs_fsverity_begin_enable,
	.end_enable_verity		= xfs_fsverity_end_enable,
	.get_verity_descriptor		= xfs_fsverity_get_descriptor,
	.read_merkle_tree_page		= xfs_fsverity_read_merkle,
	.write_merkle_tree_block	= xfs_fsverity_write_merkle,
	.file_corrupt			= xfs_fsverity_file_corrupt,
};
