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
		.value		= buf,
		.valuelen	= buf_size,
	};

	/*
	 * The fact that (returned attribute size) == (provided buf_size) is
	 * checked by xfs_attr_copy_value() (returns -ERANGE)
	 */
	error = xfs_attr_get(&args);
	if (error)
		return error;

	return args.valuelen;
}

static int
xfs_begin_enable_verity(
	struct file	    *filp)
{
	struct inode	    *inode = file_inode(filp);
	struct xfs_inode    *ip = XFS_I(inode);
	int		    error = 0;

	ASSERT(xfs_isilocked(ip, XFS_IOLOCK_EXCL));

	if (IS_DAX(inode))
		return -EINVAL;

	if (xfs_iflags_test(ip, XFS_IVERITY_CONSTRUCTION))
		return -EBUSY;
	xfs_iflags_set(ip, XFS_IVERITY_CONSTRUCTION);

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

	ASSERT(xfs_isilocked(ip, XFS_IOLOCK_EXCL));

	/* fs-verity failed, just cleanup */
	if (desc == NULL) {
		goto out;
	}

	error = xfs_attr_set(&args);
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
	xfs_iflags_clear(ip, XFS_IVERITY_CONSTRUCTION);
	return error;
}

static struct page *
xfs_read_merkle_tree_page(
	struct inode		*inode,
	pgoff_t			index,
	unsigned long		num_ra_pages,
	u8			log_blocksize,
	void			**fs_private)
{
	struct xfs_inode	*ip = XFS_I(inode);
	struct page		*page = NULL;
	__be64			name = cpu_to_be64(index << PAGE_SHIFT);
	uint32_t bs		= 1 << log_blocksize;
	int blocks_per_page	= (1 << (PAGE_SHIFT - log_blocksize));
	int n			= 0;
	struct xfs_da_args	args = {
		.dp		= ip,
		.attr_filter	= XFS_ATTR_VERITY,
		.op_flags	= XFS_DA_OP_BUFFER,
		.name		= (const uint8_t *)&name,
		.namelen	= sizeof(__be64),
		.valuelen	= bs,
	};
	int			error = 0;

	error = xfs_attr_get(&args);
	if (error)
		return ERR_PTR(-EFAULT);

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		xfs_buf_rele(args.bp);
		return ERR_PTR(-ENOMEM);
	}

	if (args.bp->b_flags & XBF_VERITY_CHECKED)
		SetPageChecked(page);

	/*
	 * Only first buffer is used to track XBF_VERITY_CHECKED state
	 * as page is always obtained as a whole
	 */
	*fs_private = (void*)args.bp;
	memcpy(page_address(page), args.value, args.valuelen);

	/*
	 * Fill the page with Merkle tree pages. This can happen if fs block
	 * size < PAGE_SIZE or Merkle tree block size < PAGE SIZE
	 */
	for (n = 1; n < blocks_per_page; n++) {
		name = cpu_to_be64(((index << PAGE_SHIFT) + bs*n));
		args.op_flags = 0;
		args.name = (const uint8_t *)&name;
		kmem_free(args.value);
		args.value = NULL;

		error = xfs_attr_get(&args);
		/*
		 * No more Merkle tree blocks (e.g. this was the last block of
		 * the tree)
		 */
		if (error == -ENOATTR)
			return page;

		if (!error)
			memcpy(page_address(page) + bs * n, args.value,
					args.valuelen);
		else {
			kmem_free(args.value);
			return ERR_PTR(-EFAULT);
		}
	}

	return page;
}

static int
xfs_write_merkle_tree_block(
	struct inode		*inode,
	const void		*buf,
	u64			pos,
	unsigned int		size)
{
	struct xfs_inode	*ip = XFS_I(inode);
	__be64			name = cpu_to_be64(pos);
	struct xfs_da_args	args = {
		.dp		= ip,
		.whichfork	= XFS_ATTR_FORK,
		.attr_filter	= XFS_ATTR_VERITY,
		.attr_flags	= XATTR_CREATE,
		.name		= (const uint8_t *)&name,
		.namelen	= sizeof(__be64),
		.value		= (void *)buf,
		.valuelen	= size,
	};

	return xfs_attr_set(&args);
}

static void
xfs_drop_page(
	struct page	*page,
	void		*fs_private)
{
	struct xfs_buf *buf = (struct xfs_buf*)fs_private;

	ASSERT(buf != NULL);

	if (PageChecked(page))
		buf->b_flags |= XBF_VERITY_CHECKED;

	xfs_buf_rele(buf);

	put_page(page);
}

const struct fsverity_operations xfs_verity_ops = {
	.begin_enable_verity = &xfs_begin_enable_verity,
	.end_enable_verity = &xfs_end_enable_verity,
	.get_verity_descriptor = &xfs_get_verity_descriptor,
	.read_merkle_tree_page = &xfs_read_merkle_tree_page,
	.write_merkle_tree_block = &xfs_write_merkle_tree_block,
	.drop_page = &xfs_drop_page,
};
