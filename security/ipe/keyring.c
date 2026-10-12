// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/key.h>

#include "keyring.h"

struct key *ipe_keyring __ro_after_init;

/**
 * ipe_keyring_init() - Allocate and configure the IPE keyring.
 *
 * Return: Always %0.
 */
int __init ipe_keyring_init(void)
{
	ipe_keyring =
		keyring_alloc(".ipe", GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
			      current_cred(), KEY_POS_SEARCH |
				KEY_USR_VIEW | KEY_USR_READ | KEY_USR_WRITE |
				KEY_USR_SEARCH | KEY_USR_SETATTR,
			      KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(ipe_keyring))
		panic("failed to allocate \".ipe\" keyring");
	return 0;
}
