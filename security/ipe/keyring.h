/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef _IPE_KEYRING_H
#define _IPE_KEYRING_H

#include <linux/init.h>

struct key;

extern struct key *ipe_keyring;

int __init ipe_keyring_init(void);

#endif /* _IPE_KEYRING_H */
