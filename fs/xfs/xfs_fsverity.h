/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */
#ifndef __XFS_FSVERITY_H__
#define __XFS_FSVERITY_H__

#ifdef CONFIG_FS_VERITY
extern const struct fsverity_operations xfs_fsverity_ops;
#endif	/* CONFIG_FS_VERITY */

#endif	/* __XFS_FSVERITY_H__ */
