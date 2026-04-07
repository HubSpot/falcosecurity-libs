// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/syscalls_dispatcher.h>
#include <bpf/bpf_helpers.h>
#include <helpers/interfaces/fixed_size_event.h>

SEC("tp_btf/sys_exit")
int BPF_PROG(t_hotplug) {
	/* We assume that the ring buffer for CPU 0 is always there so we send the
	 * HOT-PLUG event through this buffer.
	 */
	uint32_t cpu_0 = 0;
	struct ringbuf_map *rb = bpf_map_lookup_elem(&ringbuf_maps, &cpu_0);
	if(!rb) {
		bpf_printk("unable to obtain the ring buffer for CPU 0");
		return 0;
	}

	struct counter_map *counter = bpf_map_lookup_elem(&counter_maps, &cpu_0);
	if(!counter) {
		bpf_printk("unable to obtain the counter map for CPU 0");
		return 0;
	}

	/* This counts the event seen by the drivers even if they are dropped because the buffer is
	 * full. */
	counter->n_evts++;

	/* If we are not able to reserve space we stop here
	 * the event collection.
	 */
	struct ringbuf_struct ringbuf;
	ringbuf.reserved_event_size = CPU_HOTPLUG_E_SIZE;
	ringbuf.event_type = PPME_CPU_HOTPLUG_E;
	ringbuf.data = bpf_ringbuf_reserve(rb, CPU_HOTPLUG_E_SIZE, 0);
	if(!ringbuf.data) {
		counter->n_drops_buffer++;
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS ===========================*/

	/* Parameter 1: cpu (type: PT_UINT32) */
	uint32_t current_cpu_id = (uint32_t)bpf_get_smp_processor_id();
	ringbuf__store_u32(&ringbuf, current_cpu_id);

	/* Parameter 2: action (type: PT_UINT32) */
	/* Right now we don't have actions we always send 0 */
	ringbuf__store_u32(&ringbuf, 0);

	/*=============================== COLLECT PARAMETERS ===========================*/

	ringbuf__submit_event(&ringbuf);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(t_drop_e) {
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, DROP_E_SIZE, PPME_DROP_E)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS ===========================*/

	ringbuf__store_u32(&ringbuf, maps__get_sampling_ratio());

	/*=============================== COLLECT PARAMETERS ===========================*/

	ringbuf__submit_event(&ringbuf);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(t_drop_x) {
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, DROP_X_SIZE, PPME_DROP_X)) {
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS ===========================*/

	ringbuf__store_u32(&ringbuf, maps__get_sampling_ratio());

	/*=============================== COLLECT PARAMETERS ===========================*/

	ringbuf__submit_event(&ringbuf);
	return 0;
}

enum custom_sys_exit_logic_codes {
	T_HOTPLUG,
	T_DROP_E,
	T_DROP_X,
	T_FILTER,
	// add more codes here.
	T_CUSTOM_MAX,
};

SEC("tp_btf/sys_exit")
int BPF_PROG(t_filter, struct pt_regs *regs, long ret) {
	uint32_t syscall_id = extract__syscall_id(regs);

	struct filter_map_entry *filter = maps__get_filter_for_syscall_num(syscall_id);
	if(filter != NULL) {
		const void *syscall_arg_ptr = (const void *)extract__syscall_argument(regs, filter->arg_num);
		int num_filter_limit;
		if(filter->num_prefixes > 12) {
			num_filter_limit = 12;
		} else {
			num_filter_limit = filter->num_prefixes;
		}
		char syscall_arg_prefix[32] = {0};
		bpf_probe_read_user_str(syscall_arg_prefix, 32, syscall_arg_ptr);
		for(int filter_idx = 0; filter_idx < num_filter_limit; filter_idx++) {
			int match = 1;
			if(filter->prefixes[filter_idx][0] == '\0') {
				break;
			}
			for(int i = 0; i < 32; i++) {
				if(syscall_arg_prefix[i] == '\0' || filter->prefixes[filter_idx][i] == '\0') {
					break;
				}
				if(filter->prefixes[filter_idx][i] != syscall_arg_prefix[i]) {
					match = 0;
					break;
				}
			}
			if(match == 1) {
				return 0;
			}
		}
	}

	bpf_tail_call(ctx, &syscall_exit_tail_table, syscall_id);
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, T_CUSTOM_MAX);
	__uint(key_size, sizeof(__u32));
	__array(values, int(void *));
} custom_sys_exit_calls SEC(".maps") = {
        .values =
                {
                        [T_HOTPLUG] = (void *)&t_hotplug,
                        [T_DROP_E] = (void *)&t_drop_e,
                        [T_DROP_X] = (void *)&t_drop_x,
                        [T_FILTER] = (void *)&t_filter,
                },
};

static __always_inline bool sampling_logic_exit(void *ctx, uint32_t id) {
	/* If dropping mode is not enabled we don't perform any sampling
	 * false: means don't drop the syscall
	 * true: means drop the syscall
	 *
	 * Use a single map lookup for capture_settings to avoid the compiler
	 * eliding null checks on subsequent lookups, which causes BPF verifier
	 * failures with some clang versions.
	 */
	struct capture_settings *settings = maps__get_capture_settings();
	if(!settings || !settings->dropping_mode) {
		return false;
	}

	uint8_t sampling_flag = maps__64bit_sampling_syscall_table(id);

	if(sampling_flag == UF_NEVER_DROP) {
		return false;
	}

	if(sampling_flag == UF_ALWAYS_DROP) {
		return true;
	}

	if((bpf_ktime_get_boot_ns() % SECOND_TO_NS) >= (SECOND_TO_NS / settings->sampling_ratio)) {
		/* If we are starting the dropping phase we need to notify the userspace, otherwise, we
		 * simply drop our event.
		 * PLEASE NOTE: this logic is not per-CPU so it is best effort!
		 */
		if(!is_dropping) {
			/* Here we are not sure we can send the drop_e event to userspace
			 * if the buffer is full, but this is not essential even if we lose
			 * an iteration we will synchronize again the next time the logic is enabled.
			 */
			is_dropping = true;
			bpf_tail_call(ctx, &custom_sys_exit_calls, T_DROP_E);
			bpf_printk("unable to tail call into 'drop_e' prog");
		}
		return true;
	}

	if(is_dropping) {
		is_dropping = false;
		bpf_tail_call(ctx, &custom_sys_exit_calls, T_DROP_X);
		bpf_printk("unable to tail call into 'drop_x' prog");
	}

	return false;
}

#define X86_64_NR_EXECVE 59
#define X86_64_NR_EXECVEAT 322

/* From linux tree: /include/trace/events/syscall.h
 * TP_PROTO(struct pt_regs *regs, long ret),
 */
SEC("tp_btf/sys_exit")
int BPF_PROG(sys_exit, struct pt_regs *regs, long ret) {
	int socketcall_syscall_id = -1;

	uint32_t syscall_id = extract__syscall_id(regs);

	if(bpf_in_ia32_syscall()) {
#if defined(__TARGET_ARCH_x86)
		if(syscall_id == __NR_ia32_socketcall) {
			socketcall_syscall_id = __NR_ia32_socketcall;
		} else {
			/*
			 * When a process does execve from 64bit to 32bit, TS_COMPAT is marked true
			 * but the id of the syscall is __NR_execve, so to correctly parse it we need to
			 * use 64bit syscall table. On 32bit __NR_execve is equal to __NR_ia32_oldolduname
			 * which is a very old syscall, not used anymore by most applications
			 */
			if(syscall_id != X86_64_NR_EXECVE && syscall_id != X86_64_NR_EXECVEAT) {
				syscall_id = maps__ia32_to_64(syscall_id);
				if(syscall_id == (uint32_t)-1) {
					return 0;
				}
			}
		}
#else
		// TODO: unsupported
		return 0;
#endif
	} else {
#ifdef __NR_socketcall
		socketcall_syscall_id = __NR_socketcall;
#endif
	}

	// We convert it here in this way the syscall will be treated exactly as the original one.
	if(syscall_id == socketcall_syscall_id) {
		int socketcall_call = (int)extract__syscall_argument(regs, 0);
		syscall_id = syscalls_dispatcher__convert_socketcall_call_to_syscall_id(socketcall_call);
		if(syscall_id == -1) {
			// We can't do anything since modern bpf filler jump table is syscall indexed
			return 0;
		}
	}

	if(!syscalls_dispatcher__64bit_interesting_syscall(syscall_id)) {
		return 0;
	}

	if(sampling_logic_exit(ctx, syscall_id)) {
		return 0;
	}

	if(maps__get_drop_failed() && ret < 0) {
		return 0;
	}

	// If we cannot find a ring buffer for this CPU we probably have an hotplug event. It's ok to
	// check only in the exit path since we will always have at least one exit syscall enabled. If
	// we change our architecture we may need to update this logic.
	struct ringbuf_map *rb = maps__get_ringbuf_map();
	if(!rb) {
		bpf_tail_call(ctx, &custom_sys_exit_calls, T_HOTPLUG);
		bpf_printk("failed to tail call into the 'hotplug' prog");
		return 0;
	}

	bpf_tail_call(ctx, &custom_sys_exit_calls, T_FILTER);

	return 0;
}
