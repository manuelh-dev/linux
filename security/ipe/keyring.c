// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/key.h>
#include <linux/moduleparam.h>

#include "ipe.h"
#include "keyring.h"

static struct key *ipe_keyring __ro_after_init;

static bool ipe_keyring_unsealed __ro_after_init;

/* Set the right module name for built-in parameters. */
#ifdef KBUILD_MODNAME
#undef KBUILD_MODNAME
#define KBUILD_MODNAME "ipe"
#endif

module_param_named(keyring_unsealed, ipe_keyring_unsealed, bool, 0444);
MODULE_PARM_DESC(keyring_unsealed, "Leave the IPE keyring unsealed");

/**
 * ipe_keyring_lookup() - Get the IPE keyring if it is ready for use.
 *
 * Return: A borrowed pointer to the IPE keyring if it is nonempty and
 * restricted, or %NULL otherwise. The keyring has system lifetime.
 */
struct key *ipe_keyring_lookup(void)
{
	if (!ipe_keyring)
		return NULL;

	if (!READ_ONCE(ipe_keyring->keys.nr_leaves_on_tree) ||
	    !READ_ONCE(ipe_keyring->restrict_link))
		return NULL;

	return ipe_keyring;
}

/**
 * ipe_keyring_init() - Allocate and configure the IPE keyring.
 *
 * Return: Always %0. A failure leaves IPE without its dedicated keyring.
 */
int __init ipe_keyring_init(void)
{
	struct key *keyring;
	int rc;

	keyring = keyring_alloc(".ipe", GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
				current_cred(),
				KEY_POS_SEARCH |
				KEY_USR_VIEW | KEY_USR_READ | KEY_USR_WRITE |
				KEY_USR_SEARCH | KEY_USR_SETATTR,
				KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(keyring)) {
		pr_err("failed to allocate keyring: %ld\n", PTR_ERR(keyring));
		return 0;
	}

	if (!ipe_keyring_unsealed) {
		rc = keyring_restrict(make_key_ref(keyring, true), NULL, NULL);
		if (rc) {
			pr_err("failed to restrict keyring: %d\n", rc);
			key_revoke(keyring);
			key_put(keyring);
			return 0;
		}
	}

	ipe_keyring = keyring;
	key_register_ipe_keyring(ipe_keyring);

	return 0;
}
