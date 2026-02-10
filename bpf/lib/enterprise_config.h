/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "static_data.h"

/* Declare an enterprise-specific global configuration variable. Access the
 * variable using the CONFIG() macro.
 */
#define DECLARE_ENTERPRISE_CONFIG(type, name, description) \
	DECLARE_CONFIG_KIND("enterprise", type, name, description)
