// SPDX-License-Identifier: GPL-2.0
//
// trace-ktls: capture plaintext from kTLS connections using eBPF.
//
// Hooks tls_sw_sendmsg (TX) and tls_sw_recvmsg (RX) in the kernel's
// TLS ULP to observe data *before* encryption and *after* decryption.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/types.h>

#define MAX_DATA_SIZE 256
#define DIR_TX 0
#define DIR_RX 1

struct event {
	gadget_timestamp timestamp_raw;
	gadget_comm      comm[TASK_COMM_LEN];
	gadget_pid       pid;
	gadget_tid       tid;
	gadget_uid       uid;
	__u8             dir_raw;
	__u32            len;
	__u32            captured;
	__u8             data[MAX_DATA_SIZE];
};

GADGET_TRACER_MAP(events, 256 * 1024);
GADGET_TRACER(ktls, events, event);

// ── helpers ─────────────────────────────────────────────────────────

static __always_inline void fill_process(struct event *e)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->timestamp_raw = bpf_ktime_get_boot_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// Read the first chunk of plaintext from a msghdr's iov_iter.
static __always_inline void
capture_plaintext(struct event *e, struct msghdr *msg, __u32 total)
{
	__u8 iter_type;
	unsigned long iov_offset;
	void *base = NULL;

	bpf_core_read(&iter_type, sizeof(iter_type), &msg->msg_iter.iter_type);
	bpf_core_read(&iov_offset, sizeof(iov_offset), &msg->msg_iter.iov_offset);

	if (iter_type == ITER_UBUF) {
		bpf_core_read(&base, sizeof(base),
			      &msg->msg_iter.__ubuf_iovec.iov_base);
	} else if (iter_type == ITER_IOVEC) {
		const struct iovec *iov;
		bpf_core_read(&iov, sizeof(iov), &msg->msg_iter.__iov);
		if (!iov)
			return;
		bpf_core_read(&base, sizeof(base), &iov->iov_base);
	}

	if (!base)
		return;

	base += iov_offset;

	__u32 to_read = total;
	if (to_read > MAX_DATA_SIZE)
		to_read = MAX_DATA_SIZE;

	e->captured = to_read;
	bpf_probe_read_user(e->data, to_read & 0x1ff, base);
}

// ── TX path ─────────────────────────────────────────────────────────

SEC("kprobe/tls_sw_sendmsg")
int BPF_KPROBE(trace_tls_tx, struct sock *sk, struct msghdr *msg, size_t size)
{
	struct event *e = gadget_reserve_buf(&events, sizeof(*e));
	if (!e)
		return 0;

	fill_process(e);
	e->dir_raw = DIR_TX;
	e->len = (__u32)size;
	e->captured = 0;

	capture_plaintext(e, msg, e->len);

	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

// ── RX path ─────────────────────────────────────────────────────────
// We snapshot the user-buffer pointer on entry (before the kernel
// advances iov_offset), then read decrypted plaintext on return.

struct rx_info {
	void *buf;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct rx_info);
} rx_args SEC(".maps");

SEC("kprobe/tls_sw_recvmsg")
int BPF_KPROBE(trace_tls_rx_enter, struct sock *sk, struct msghdr *msg)
{
	struct rx_info info = {};
	__u8 iter_type;

	bpf_core_read(&iter_type, sizeof(iter_type), &msg->msg_iter.iter_type);

	if (iter_type == ITER_UBUF) {
		bpf_core_read(&info.buf, sizeof(info.buf),
			      &msg->msg_iter.__ubuf_iovec.iov_base);
	} else if (iter_type == ITER_IOVEC) {
		const struct iovec *iov;
		bpf_core_read(&iov, sizeof(iov), &msg->msg_iter.__iov);
		if (iov)
			bpf_core_read(&info.buf, sizeof(info.buf),
				      &iov->iov_base);
	}

	if (!info.buf)
		return 0;

	unsigned long off;
	bpf_core_read(&off, sizeof(off), &msg->msg_iter.iov_offset);
	info.buf += off;

	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&rx_args, &id, &info, BPF_ANY);
	return 0;
}

SEC("kretprobe/tls_sw_recvmsg")
int BPF_KRETPROBE(trace_tls_rx_exit, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct rx_info *info = bpf_map_lookup_elem(&rx_args, &id);
	if (!info)
		return 0;

	void *buf = info->buf;
	bpf_map_delete_elem(&rx_args, &id);

	if (ret <= 0)
		return 0;

	struct event *e = gadget_reserve_buf(&events, sizeof(*e));
	if (!e)
		return 0;

	fill_process(e);
	e->dir_raw = DIR_RX;
	e->len = (__u32)ret;

	__u32 to_read = (__u32)ret;
	if (to_read > MAX_DATA_SIZE)
		to_read = MAX_DATA_SIZE;
	e->captured = to_read;
	bpf_probe_read_user(e->data, to_read & 0x1ff, buf);

	gadget_submit_buf(ctx, &events, e, sizeof(*e));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
