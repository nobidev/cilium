// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include "common.h"
#include <bpf/config/node.h>

#include <lib/time.h>

static __u64 mock_ktime_get_ns(void)
{
	return 3000 * NSEC_PER_SEC;
}

#define ktime_get_ns mock_ktime_get_ns

#include "lib/ratelimit.h"

CHECK("xdp", "ratelimit") int test_ratelimit(void)
{
	struct ratelimit_key key = {
		.usage = RATELIMIT_USAGE_ICMPV6,
		.key = {
			.icmpv6 = {
				.netdev_idx = 1,
			},
		},
	};
	__u64 topup_interval_ns = NSEC_PER_SEC;
	struct ratelimit_value *value;
	__u64 tokens_per_topup = 100;
	__u64 bucket_size = 1000;

	test_init();

	TEST("bucket-created-when-missing", {
		value = map_lookup_elem(&cilium_ratelimit, &key);
		if (value)
			test_fatal("Bucket already exits");

		ratelimit_check_and_take(&key, bucket_size, tokens_per_topup, topup_interval_ns);

		value = map_lookup_elem(&cilium_ratelimit, &key);
		if (!value)
			test_fatal("Bucket not created");
	})

	TEST("block-on-bucket-empty", {
		value = map_lookup_elem(&cilium_ratelimit, &key);
		if (!value)
			test_fatal("Bucket not created");

		value->tokens = 1;
		if (!ratelimit_check_and_take(&key, bucket_size, tokens_per_topup, topup_interval_ns))
			test_fatal("Rate limit not allowed when bucket not empty");

		if (value->tokens != 0)
			test_fatal("Bucket not empty");

		if (ratelimit_check_and_take(&key, bucket_size, tokens_per_topup, topup_interval_ns))
			test_fatal("Rate limit allowed when bucket empty");
	})

	TEST("topup-after-interval", {
		value = map_lookup_elem(&cilium_ratelimit, &key);
		if (!value)
			test_fatal("Bucket not created");

		/* Set last topup to 1 interval ago */
		value->tokens = 0;
		value->last_topup = ktime_get_ns() - (topup_interval_ns + 1);

		if (!ratelimit_check_and_take(&key, bucket_size, tokens_per_topup, topup_interval_ns))
			test_fatal("Rate limit not allowed after topup");

		if (value->tokens != tokens_per_topup - 1)
			test_fatal("Unexpected token amount after topup");
	})

	TEST("do-not-go-over-bucket-size", {
		value = map_lookup_elem(&cilium_ratelimit, &key);
		if (!value)
			test_fatal("Bucket not created");

		/* Set last topup to 100 intervals ago */
		value->tokens = 0;
		value->last_topup = ktime_get_ns() - (100 * topup_interval_ns);

		if (!ratelimit_check_and_take(&key, bucket_size, tokens_per_topup, topup_interval_ns))
			test_fatal("Rate limit not allowed after topup");

		if (value->tokens != bucket_size - 1)
			test_fatal("Unexpected token amount after topup");
	})

	test_finish();
}
