// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */
#ifndef __XFS_VERITY_H__
#define __XFS_VERITY_H__

#include <linux/fsverity.h>

#define XFS_VERITY_DESCRIPTOR_NAME "verity_descriptor"
#define XFS_VERITY_DESCRIPTOR_NAME_LEN 17

#ifdef CONFIG_FS_VERITY
extern const struct fsverity_operations xfs_verity_ops;
#else
#define xfs_verity_ops NULL
#endif	/* CONFIG_FS_VERITY */

/* Minimal Merkle tree block size is 1024 */
#define XFS_VERITY_MAX_MBLOCKS_PER_PAGE (1 << (PAGE_SHIFT - 10))

struct xfs_verity_buf_list {
	unsigned int	buf_count;
	struct xfs_buf	*bufs[XFS_VERITY_MAX_MBLOCKS_PER_PAGE];
};

#endif	/* __XFS_VERITY_H__ */
