/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 Red Hat, Inc.
 */
#include "xfs_platform.h"
#include "xfs_format.h"
#include "xfs_inode.h"
#include "xfs_shared.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_fsverity.h"
#include "xfs_fsverity.h"
#include <linux/fsverity.h>
#include <linux/iomap.h>

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
