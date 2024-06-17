// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, SUSE. */

#include "mptcp_bpf.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct mptcp_red_storage {
	u8 cnt;
	u8 reinject;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct mptcp_red_storage);
} mptcp_red_map SEC(".maps");

SEC("struct_ops")
void BPF_PROG(mptcp_sched_red_init, struct mptcp_sock *msk)
{
	bpf_sk_storage_get(&mptcp_red_map, msk, 0,
			   BPF_LOCAL_STORAGE_GET_F_CREATE);
}

SEC("struct_ops")
void BPF_PROG(mptcp_sched_red_release, struct mptcp_sock *msk)
{
	bpf_sk_storage_delete(&mptcp_red_map, msk);
}

SEC("struct_ops")
int BPF_PROG(bpf_red_get_subflow, struct mptcp_sock *msk,
	     struct mptcp_sched_data *data)
{
	struct mptcp_red_storage *ptr;

	ptr = bpf_sk_storage_get(&mptcp_red_map, msk, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return -1;

	ptr->cnt = 0;
	ptr->reinject = data->reinject;
	for (int i = 0; i < data->subflows && i < MPTCP_SUBFLOWS_MAX; i++) {
		if (!bpf_mptcp_subflow_ctx_by_pos(data, i))
			break;

		mptcp_subflow_set_scheduled(bpf_mptcp_subflow_ctx_by_pos(data, i), true);
		ptr->cnt++;
	}

	return 0;
}

SEC("struct_ops")
void BPF_PROG(bpf_red_push, struct mptcp_sock *msk,
	      struct mptcp_subflow_context *subflow,
	      struct mptcp_sched_chunk *chunk)
{
	struct mptcp_red_storage *ptr;

	ptr = bpf_sk_storage_get(&mptcp_red_map, msk, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return;

	// Reinject if there are other subflows available and
	// if this is not already a "real" reinjection.
	if (ptr->cnt > 1 && !ptr->reinject) {
		chunk->flags |= MPTCP_SCHED_FLAG_REINJECT;
	}
	ptr->cnt--;

	return ;
}

SEC(".struct_ops")
struct mptcp_sched_ops red = {
	.init		= (void *)mptcp_sched_red_init,
	.release	= (void *)mptcp_sched_red_release,
	.get_subflow	= (void *)bpf_red_get_subflow,
	.push		= (void *)bpf_red_push,
	.name		= "bpf_red",
};
