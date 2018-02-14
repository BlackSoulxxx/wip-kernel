# SPDX-License-Identifier: GPL-2.0
#
# Makefile for building the Linux Kernel Runtime Guard (LKRG)  module as part of the kernel tree.
#
lkrg-y = \
		modules/ksyms/p_resolve_ksym.o \
		modules/hashing/p_lkrg_fast_hash.o \
		modules/comm_channel/p_comm_channel.o \
		modules/wrap/p_struct_wrap.o \
		modules/integrity_timer/p_integrity_timer.o \
		modules/kmod/p_kmod.o \
		modules/database/CPU.o \
		modules/database/arch/x86/IDT_MSR_CRx.o \
		modules/database/p_database.o \
		modules/notifiers/p_notifiers.o \
		modules/self-defense/hiding/p_hiding.o \
		modules/exploit_detection/p_rb_ed_trees/p_rb_ed_pids/p_rb_ed_pids_tree.o \
		modules/exploit_detection/syscalls/p_sys_execve/p_sys_execve.o \
		modules/exploit_detection/syscalls/p_sys_execveat/p_sys_execveat.o \
		src/modules/exploit_detection/syscalls/p_call_usermodehelper/p_call_usermodehelper.o \
		modules/exploit_detection/syscalls/p_do_exit/p_do_exit.o \
		modules/exploit_detection/syscalls/p_do_fork/p_do_fork.o \
		modules/exploit_detection/syscalls/p_sys_setuid/p_sys_setuid.o \
		modules/exploit_detection/syscalls/p_sys_setreuid/p_sys_setreuid.o \
		modules/exploit_detection/syscalls/p_sys_setresuid/p_sys_setresuid.o \
		modules/exploit_detection/syscalls/p_sys_setfsuid/p_sys_setfsuid.o \
		modules/exploit_detection/syscalls/p_sys_setgid/p_sys_setgid.o \
		modules/exploit_detection/syscalls/p_sys_setregid/p_sys_setregid.o \
		modules/exploit_detection/syscalls/p_sys_setresgid/p_sys_setresgid.o \
		modules/exploit_detection/syscalls/p_sys_setfsgid/p_sys_setfsgid.o \
		modules/exploit_detection/syscalls/p_sys_setgroups/p_sys_setgroups.o \
		modules/exploit_detection/syscalls/p_do_init_module/p_do_init_module.o \
		modules/exploit_detection/syscalls/p_sys_finit_module/p_sys_finit_module.o \
		modules/exploit_detection/syscalls/p_sys_delete_module/p_sys_delete_module.o \
		modules/exploit_detection/syscalls/p_may_open/p_may_open.o \
		modules/exploit_detection/syscalls/p_sel_write_enforce/p_sel_write_enforce.o \
		modules/exploit_detection/syscalls/p_seccomp/p_seccomp.o \
		modules/exploit_detection/syscalls/p_sys_unshare/p_sys_unshare.o \
		modules/exploit_detection/syscalls/p_userns_install/p_userns_install.o \
		modules/exploit_detection/syscalls/caps/p_sys_capset/p_sys_capset.o \
		modules/exploit_detection/syscalls/caps/p_cap_task_prctl/p_cap_task_prctl.o \
		modules/exploit_detection/syscalls/keyring/p_key_change_session_keyring/p_key_change_session_keyring.o \
		modules/exploit_detection/syscalls/keyring/p_sys_add_key/p_sys_add_key.o \
		modules/exploit_detection/syscalls/keyring/p_sys_request_key/p_sys_request_key.o \
		modules/exploit_detection/syscalls/keyring/p_sys_keyctl/p_sys_keyctl.o \
		modules/exploit_detection/syscalls/p_sys_ptrace/p_sys_ptrace.o \
		modules/exploit_detection/syscalls/compat/p_compat_sys_execve/p_compat_sys_execve.o \
		modules/exploit_detection/syscalls/compat/p_compat_sys_execveat/p_compat_sys_execveat.o \
		modules/exploit_detection/syscalls/compat/p_compat_sys_keyctl/p_compat_sys_keyctl.o \
		modules/exploit_detection/syscalls/compat/p_compat_sys_ptrace/p_compat_sys_ptrace.o \
		modules/exploit_detection/p_exploit_detection.o \
		p_lkrg_main.o

obj-$(CONFIG_LKRG) := lkrg.o

ccflags-y += -I$(srctree)/drivers/staging/lkrg -I$(srctree)/drivers/staging/lkrg/modules
