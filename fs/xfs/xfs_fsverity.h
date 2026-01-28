/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */
#ifndef __XFS_FSVERITY_H__
#define __XFS_FSVERITY_H__

#ifdef CONFIG_FS_VERITY
extern const struct fsverity_operations xfs_fsverity_ops;
loff_t xfs_fsverity_pos(struct xfs_inode *ip);
xfs_fileoff_t xfs_fsverity_disk_offset(struct xfs_inode *ip);
loff_t xfs_fsverity_pos_memory_disk(struct xfs_inode *ip, loff_t pos);
loff_t xfs_fsverity_offset_disk_memory(struct xfs_inode *ip, loff_t offset);
#endif	/* CONFIG_FS_VERITY */

#endif	/* __XFS_FSVERITY_H__ */
