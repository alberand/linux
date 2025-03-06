/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 Red Hat, Inc.
 */
#ifndef __XFS_FSVERITY_H__
#define __XFS_FSVERITY_H__

#include "xfs_platform.h"

#ifdef CONFIG_FS_VERITY
loff_t xfs_fsverity_metadata_offset(const struct xfs_inode *ip);
#else
static inline loff_t xfs_fsverity_metadata_offset(const struct xfs_inode *ip)
{
	WARN_ON_ONCE(1);
	return ULLONG_MAX;
}
#endif	/* CONFIG_FS_VERITY */

#endif	/* __XFS_FSVERITY_H__ */
