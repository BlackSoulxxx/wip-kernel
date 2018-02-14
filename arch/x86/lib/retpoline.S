/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/stringify.h>
#include <linux/linkage.h>
#include <asm/dwarf2.h>
#include <asm/cpufeatures.h>
#include <asm/alternative-asm.h>
#include <asm/export.h>
#include <asm/nospec-branch.h>

#ifdef CONFIG_RETPOLINE

.macro THUNK reg
	.section .text.__x86.indirect_thunk

ENTRY(__x86_indirect_thunk_\reg)
	CFI_STARTPROC
	JMP_NOSPEC %\reg
	CFI_ENDPROC
ENDPROC(__x86_indirect_thunk_\reg)
.endm

/*
 * Despite being an assembler file we can't just use .irp here
 * because __KSYM_DEPS__ only uses the C preprocessor and would
 * only see one instance of "__x86_indirect_thunk_\reg" rather
 * than one per register with the correct names. So we do it
 * the simple and nasty way...
 */
#define __EXPORT_THUNK(sym) _ASM_NOKPROBE(sym); EXPORT_SYMBOL(sym)
#define EXPORT_THUNK(reg) __EXPORT_THUNK(__x86_indirect_thunk_ ## reg)
#define GENERATE_THUNK(reg) THUNK reg ; EXPORT_THUNK(reg)

GENERATE_THUNK(_ASM_AX)
GENERATE_THUNK(_ASM_BX)
GENERATE_THUNK(_ASM_CX)
GENERATE_THUNK(_ASM_DX)
GENERATE_THUNK(_ASM_SI)
GENERATE_THUNK(_ASM_DI)
GENERATE_THUNK(_ASM_BP)
#ifdef CONFIG_64BIT
GENERATE_THUNK(r8)
GENERATE_THUNK(r9)
GENERATE_THUNK(r10)
GENERATE_THUNK(r11)
GENERATE_THUNK(r12)
GENERATE_THUNK(r13)
GENERATE_THUNK(r14)
GENERATE_THUNK(r15)
#else

/*
 * Clang uses this on 32-bit. It does *not* match the GCC one which
 * is equivalent to a 'ret'. Instead it takes the target address
 * followed by a return address, both on the stack. The name will
 * change back to being LLVM-specific.
 */
ENTRY(__x86_indirect_thunk)
	CFI_STARTPROC
	calll	.Lpush_call_target
.Lpush_capture_spec:
	lfence
	jmp	.Lpush_capture_spec

	.align	16

.Lpush_call_target:
	addl	$4,%esp	# Clear pause_loop return address.
	# Top of stack words are: Callee, RA. Exchange Callee and RA.
	pushl	4(%esp)	# Push callee
	pushl	4(%esp)	# Push RA
	popl	8(%esp)	# Pop RA to final RA
	popl	(%esp)	# Pop callee to next top of stack
	retl		# Ret to callee
	CFI_ENDPROC
ENDPROC(__x86_indirect_thunk)
__EXPORT_THUNK(__x86_indirect_thunk)
#endif

#endif /* CONFIG_RETPOLINE */
