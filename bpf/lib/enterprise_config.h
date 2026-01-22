/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "static_data.h"

/* Declare an enterprise-specific global configuration variable. Access the
 * variable using the CONFIG() macro.
 */
#define DECLARE_ENTERPRISE_CONFIG(type, name, description) \
	__section(__CONFIG_SECTION) \
	__attribute__((btf_decl_tag("kind:enterprise"))) \
	__attribute__((btf_decl_tag(description))) \
	volatile const type __config_##name;
