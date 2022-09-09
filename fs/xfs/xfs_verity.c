// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */
#include "xfs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_attr.h"
#include "xfs_verity.h"
#include "xfs_bmap_util.h"
#include "xfs_log_format.h"
#include "xfs_trans.h"

static int
xfs_get_verity_descriptor(
	struct inode		*inode,
	void			*buf,
	size_t			buf_size)
{
	struct xfs_inode	*ip = XFS_I(inode);
	int			error = 0;
	struct xfs_da_args	args = {
		.dp		= ip,
		.attr_filter	= XFS_ATTR_VERITY,
		.name		= (const uint8_t *)XFS_VERITY_DESCRIPTOR_NAME,
		.namelen	= XFS_VERITY_DESCRIPTOR_NAME_LEN,
		.valuelen	= buf_size,
	};

	error = xfs_attr_get(&args);
	if (error)
		return error;

	if (buf_size == 0)
		return args.valuelen;

	if (args.valuelen > buf_size) {
		kmem_free(args.value);
		return -ERANGE;
	}

	memcpy(buf, args.value, buf_size);

	kmem_free(args.value);
	return args.valuelen;
}

static int
xfs_begin_enable_verity(
	struct file	    *filp)
{
	struct inode	    *inode = file_inode(filp);
	struct xfs_inode    *ip = XFS_I(inode);
	int		    error = 0;

	if (IS_DAX(inode))
		return -EINVAL;

	if (xfs_iflags_test(ip, XFS_IVERITY))
		return -EBUSY;
	xfs_iflags_set(ip, XFS_IVERITY);

	/*
	 * As fs-verity doesn't support multi-page folios yet, flush everything
	 * from page cache and disable it
	 */
	filemap_invalidate_lock(inode->i_mapping);

	inode_dio_wait(inode);
	error = xfs_flush_unmap_range(ip, 0, XFS_ISIZE(ip));
	if (error)
		goto out;
	mapping_clear_large_folios(inode->i_mapping);

out:
	filemap_invalidate_unlock(inode->i_mapping);
	if (error)
		xfs_iflags_clear(ip, XFS_IVERITY);
	return error;
}

static int
xfs_end_enable_verity(
	struct file		*filp,
	const void		*desc,
	size_t			desc_size,
	u64			merkle_tree_size)
{
	struct inode		*inode = file_inode(filp);
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp;
	struct xfs_da_args	args = {
		.dp		= ip,
		.whichfork	= XFS_ATTR_FORK,
		.attr_filter	= XFS_ATTR_VERITY,
		.attr_flags	= XATTR_CREATE,
		.name		= (const uint8_t *)XFS_VERITY_DESCRIPTOR_NAME,
		.namelen	= XFS_VERITY_DESCRIPTOR_NAME_LEN,
		.value		= (void *)desc,
		.valuelen	= desc_size,
	};
	int			error = 0;

	/* fs-verity failed, just cleanup */
	if (desc == NULL) {
		mapping_set_large_folios(inode->i_mapping);
		goto out;
	}

	error = xfs_attr_set(&args);
	if (error)
		goto out;

	/* Set fsverity inode flag */
	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_ichange, 0, 0, 0, &tp);
	if (error)
		goto out;

	xfs_ilock(ip, XFS_ILOCK_EXCL);
	xfs_trans_ijoin(tp, ip, XFS_ILOCK_EXCL);

	ip->i_diflags2 |= XFS_DIFLAG2_VERITY;
	inode->i_flags |= S_VERITY;

	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
	error = xfs_trans_commit(tp);

out:
	if (error)
		mapping_set_large_folios(inode->i_mapping);

	xfs_iflags_clear(ip, XFS_IVERITY);
	return error;
}

static struct page *
xfs_read_merkle_tree_page(
	struct inode		*inode,
	pgoff_t			index,
	unsigned long		num_ra_pages)
{
	struct xfs_inode	*ip = XFS_I(inode);
	struct page		*page;
	__be64			name = cpu_to_be64(index);
	struct xfs_da_args	args = {
		.dp		= ip,
		.attr_filter	= XFS_ATTR_VERITY,
		.name		= (const uint8_t *)&name,
		.namelen	= sizeof(__be64),
		.valuelen	= PAGE_SIZE,
	};
	int			error = 0;

	error = xfs_attr_get(&args);
	if (error)
		return ERR_PTR(-EFAULT);

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return ERR_PTR(-ENOMEM);

	memcpy(page_address(page), args.value, args.valuelen);

	kmem_free(args.value);
	return page;
}

static int
xfs_write_merkle_tree_block(
	struct inode		*inode,
	const void		*buf,
	u64			index,
	int			log_blocksize)
{
	struct xfs_inode	*ip = XFS_I(inode);
	__be64			name = cpu_to_be64(index);
	struct xfs_da_args	args = {
		.dp		= ip,
		.whichfork	= XFS_ATTR_FORK,
		.attr_filter	= XFS_ATTR_VERITY,
		.attr_flags	= XATTR_CREATE,
		.name		= (const uint8_t *)&name,
		.namelen	= sizeof(__be64),
		.value		= (void *)buf,
		.valuelen	= 1 << log_blocksize,
	};

	return xfs_attr_set(&args);
}

const struct fsverity_operations xfs_verity_ops = {
	.begin_enable_verity = &xfs_begin_enable_verity,
	.end_enable_verity = &xfs_end_enable_verity,
	.get_verity_descriptor = &xfs_get_verity_descriptor,
	.read_merkle_tree_page = &xfs_read_merkle_tree_page,
	.write_merkle_tree_block = &xfs_write_merkle_tree_block,
};
