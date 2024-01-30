// SPDX-License-Identifier: GPL-2.0
// // Copyright (c) 2024
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "filegone.h"
#include "core_fixes.bpf.h"

#define FMODE_CREATED	0x100000

const volatile pid_t targ_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32); /* tid */
	__type(value, struct event);
} currevent SEC(".maps");

/**
 * In different kernel versions, function vfs_unlink() has two declarations,
 * and their parameter lists are as follows:
 *
 * int vfs_unlink(struct inode *dir, struct dentry *dentry,
 *        struct inode **delegated_inode);
 * int vfs_unlink(struct user_namespace *mnt_userns, struct inode *dir,
 *        struct dentry *dentry, struct inode **delegated_inode);
 * int vfs_unlink(struct mnt_idmap *idmap, struct inode *dir,
 *        struct dentry *dentry, struct inode **delegated_inode);
 */
SEC("kprobe/vfs_unlink")
int BPF_KPROBE(vfs_unlink, void *arg0, void *arg1, void *arg2)
{
	u64 id = bpf_get_current_pid_tgid();
	struct event event = {};
	const u8 *qs_name_ptr;
	//u8 action;
	u32 tgid = id >> 32;
	u32 tid = (u32)id;
	bool has_arg = renamedata_has_old_mnt_userns_field()
				|| renamedata_has_new_mnt_idmap_field();

	qs_name_ptr = has_arg
		? BPF_CORE_READ((struct dentry *)arg2, d_name.name)
		: BPF_CORE_READ((struct dentry *)arg1, d_name.name);

	bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), qs_name_ptr);
	bpf_get_current_comm(&event.task, sizeof(event.task));
	event.action = 'D';
	event.tgid = tgid;

	bpf_map_update_elem(&currevent, &tid, &event, BPF_ANY);
	return 0;
}

SEC("kprobe/vfs_rename")
int BPF_KPROBE(vfs_rename, void *arg0, void *arg1, void *arg2)
{
	u64 id = bpf_get_current_pid_tgid();
	struct event event = {};
	const u8 *qs_name_ptr;
	const u8 *qd_name_ptr;
	//u8 action;
	u32 tgid = id >> 32;
	u32 tid = (u32)id;
	//bool has_arg = renamedata_has_old_mnt_userns_field() || renamedata_has_new_mnt_idmap_field();

	qs_name_ptr = BPF_CORE_READ((struct dentry *)arg1, d_name.name);
	qd_name_ptr = BPF_CORE_READ((struct dentry *)arg2, d_name.name);

	bpf_get_current_comm(&event.task, sizeof(event.task));
	event.tgid = tgid;
	event.action = 'R';
	bpf_probe_read_kernel_str(&event.fname, sizeof(event.fname), qs_name_ptr);
	bpf_probe_read_kernel_str(&event.fname2, sizeof(event.fname2), qd_name_ptr);

	bpf_map_update_elem(&currevent, &tid, &event, BPF_ANY);
	return 0;
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(vfs_unlink_ret)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tid = (u32)id;
	int ret = PT_REGS_RC(ctx);
	struct event *event;

	event = bpf_map_lookup_elem(&currevent, &tid);
	if (!event)
		return 0;
	bpf_map_delete_elem(&currevent, &tid);

	/* skip failed unlink */
	if (ret)
		return 0;

	/* output */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      event, sizeof(*event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

