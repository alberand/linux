/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */
#ifndef __XFS_FSVERITY_H__
#define __XFS_FSVERITY_H__

#include "xfs_inode.h"
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include <linux/iomap.h>

#ifdef CONFIG_FS_VERITY

/* Merkle tree location in page cache. We take memory region from the inode's
 * address space for Merkle tree. */
#define XFS_FSVERITY_MTREE_OFFSET (1 << 30)
#define XFS_FSVERITY_MTREE_MASK (XFS_FSVERITY_MTREE_OFFSET - 1)

inline void
xfs_fsverity_init_merkle_args(
	struct xfs_inode	*ip,
	struct xfs_merkle_key	*key,
	uint64_t		merkleoff,
	struct xfs_da_args	*args);

struct xfs_merkle_bkey {
	/* inumber of the file */
	xfs_ino_t		ino;

	/* the position of the block in the Merkle tree (in bytes) */
	u64			pos;
};

int
xfs_fsverity_end_ioend(
	struct xfs_inode	*ip,
	struct iomap_ioend	*ioend);

extern const struct fsverity_operations xfs_fsverity_ops;
#else
#define xfs_fsverity_bmbt_irec(ip, key, merkleoff, args) (0)
#define xfs_fsverity_end_ioend(ip, ioend) (0)
#endif	/* CONFIG_FS_VERITY */

#endif	/* __XFS_FSVERITY_H__ */
