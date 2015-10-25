/*
 * In-kernel vhost-nvme queue handling
 *
 * Copyright (c) 2015 Datera, Inc
 *
 * Functions for vhost handling
 */

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/vhost.h>
#include <uapi/linux/vhost.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_backend.h>

#include "vhost_nvme_base.h"
