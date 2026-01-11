/*
   american fuzzy lop++ - injectable parts
   ---------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This file houses the assembly-level instrumentation injected into fuzzed
   programs. The instrumentation stores XORed pairs of data: identifiers of the
   currently executing branch and the one that executed immediately before.

   TL;DR: the instrumentation does shm_trace_map[cur_loc ^ prev_loc]++

   The code is designed for 32-bit and 64-bit x86 systems. Both modes should
   work everywhere except for Apple systems. Apple does relocations differently
   from everybody else, so since their OSes have been 64-bit for a longer while,
   I didn't go through the mental effort of porting the 32-bit code.

   In principle, similar code should be easy to inject into any well-behaved
   binary-only code (e.g., using DynamoRIO). Conditional jumps offer natural
   targets for instrumentation, and should offer comparable probe density.

 */

#ifndef _HAVE_AFL_AS_H
#define _HAVE_AFL_AS_H

#include "config.h"
#include "types.h"

/*
   ------------------
   Performances notes
   ------------------

   Contributions to make this code faster are appreciated! Here are some
   rough notes that may help with the task:

   - Only the trampoline_fmt and the non-setup __afl_maybe_log code paths are
     really worth optimizing; the setup / fork server stuff matters a lot less
     and should be mostly just kept readable.

   - We're aiming for modern CPUs with out-of-order execution and large
     pipelines; the code is mostly follows intuitive, human-readable
     instruction ordering, because "textbook" manual reorderings make no
     substantial difference.

   - Interestingly, instrumented execution isn't a lot faster if we store a
     variable pointer to the setup, log, or return routine and then do a reg
     call from within trampoline_fmt. It does speed up non-instrumented
     execution quite a bit, though, since that path just becomes
     push-call-ret-pop.

   - There is also not a whole lot to be gained by doing SHM attach at a
     fixed address instead of retrieving __afl_area_ptr. Although it allows us
     to have a shorter log routine inserted for conditional jumps and jump
     labels (for a ~10% perf gain), there is a risk of bumping into other
     allocations created by the program or by tools such as ASAN.

   - popf is *awfully* slow, which is why we're doing the lahf / sahf +
     overflow test trick. Unfortunately, this forces us to taint eax / rax, but
     this dependency on a commonly-used register still beats the alternative of
     using pushf / popf.

     One possible optimization is to avoid touching flags by using a circular
     buffer that stores just a sequence of current locations, with the XOR stuff
     happening offline. Alas, this doesn't seem to have a huge impact:

     https://groups.google.com/d/msg/afl-users/MsajVf4fRLo/2u6t88ntUBIJ

   - Preforking one child a bit sooner, and then waiting for the "go" command
     from within the child, doesn't offer major performance gains; fork() seems
     to be relatively inexpensive these days. Preforking multiple children does
     help, but badly breaks the "~1 core per fuzzer" design, making it harder to
     scale up. Maybe there is some middle ground.

   Perhaps of note: in the 64-bit version for all platforms except for Apple,
   the instrumentation is done slightly differently than on 32-bit, with
   __afl_prev_loc and __afl_area_ptr being local to the object file (.lcomm),
   rather than global (.comm). This is to avoid GOTRELPC lookups in the critical
   code path, which AFAICT, are otherwise unavoidable if we want gcc -shared to
   work; simple relocations between .bss and .text won't work on most 64-bit
   platforms in such a case.

   (Fun fact: on Apple systems, .lcomm can segfault the linker.)

   The side effect is that state transitions are measured in a somewhat
   different way, with previous tuple being recorded separately within the scope
   of every .c file. This should have no impact in any practical sense.

   Another side effect of this design is that getenv() will be called once per
   every .o file when running in non-instrumented mode; and since getenv() tends
   to be optimized in funny ways, we need to be very careful to save every
   oddball register it may touch.

 */

static const u8 *trampoline_fmt_64_intel =

    "\n"
    "/* --- AFL TRAMPOLINE (64-BIT) — .intel_syntax noprefix --- */\n"
    "\n"
    ".intel_syntax noprefix\n"
    ".align 4\n"
    "\n"
    "lea rsp, [rsp - 152]\n"
    "mov qword ptr [rsp + 0], rdx\n"
    "mov qword ptr [rsp + 8], rcx\n"
    "mov qword ptr [rsp + 16], rax\n"
    "mov rcx, 0x%08x\n"
    "call __afl_maybe_log\n"
    "mov rax, qword ptr [rsp + 16]\n"
    "mov rcx, qword ptr [rsp + 8]\n"
    "mov rdx, qword ptr [rsp + 0]\n"
    "lea rsp, [rsp + 152]\n"
    ".intel_syntax prefix\n"
    "\n"
    "/* --- END --- */\n"
    "\n";


/* The OpenBSD hack is due to lahf and sahf not being recognized by some
   versions of binutils: https://marc.info/?l=openbsd-cvs&m=141636589924400

   The Apple code is a bit different when calling libc functions because
   they are doing relocations differently from everybody else. We also need
   to work around the crash issue with .lcomm and the fact that they don't
   recognize .string. */


#define CALL_L64(str) "call " str "@PLT\n"


static const u8 *main_payload_64_intel =

  "\n"
  "/* --- AFL MAIN PAYLOAD (64-BIT) — Intel syntax --- */\n"
  "\n"
  ".text\n"
  ".intel_syntax noprefix\n"
  ".code64\n"
  ".align 8\n"
  "\n"
  "__afl_maybe_log:\n"
  "\n"
  "  lahf\n"
  "  seto  al\n"
  "\n"
  "  /* Check if SHM region is already mapped. */\n"
  "\n"
  "  mov   rdx, qword ptr [rip + __afl_area_ptr]\n"
  "  test  rdx, rdx\n"
  "  je    __afl_setup\n"
  "\n"
  "__afl_store:\n"
  "\n"
  "  /* Calculate and store hit for the code location specified in rcx. */\n"
  "\n"
#ifndef COVERAGE_ONLY
  "  xor   rcx, qword ptr [rip + __afl_prev_loc]\n"
  "  xor   qword ptr [rip + __afl_prev_loc], rcx\n"
  "  shr   qword ptr [rip + __afl_prev_loc], 1\n"
#endif                                                   /* ^!COVERAGE_ONLY */
  "\n"
#ifdef SKIP_COUNTS
  "  or    byte ptr [rdx + rcx*1], 1\n"
#else
  "  add   byte ptr [rdx + rcx*1], 1\n"
  "  adc   byte ptr [rdx + rcx*1], 0\n" // never-zero counter
#endif                                                      /* ^SKIP_COUNTS */
  "\n"
  "__afl_return:\n"
  "\n"
  "  add   al, 127\n"
  "  sahf\n"
  "  ret\n"
  "\n"
  ".align 8\n"
  "\n"
  "__afl_setup:\n"
  "\n"
  "  /* Do not retry setup if we had previous failures. */\n"
  "\n"
  "  cmp   byte ptr [rip + __afl_setup_failure], 0\n"
  "  jne   __afl_return\n"
  "\n"
  "  /* Check out if we have a global pointer on file. */\n"
  "\n"
  "  mov   rdx, qword ptr [rip + __afl_global_area_ptr@GOTPCREL]\n"
  "  mov   rdx, qword ptr [rdx]\n"
  "  test  rdx, rdx\n"
  "  je    __afl_setup_first\n"
  "\n"
  "  mov   qword ptr [rip + __afl_area_ptr], rdx\n"
  "  jmp   __afl_store\n"
  "\n"
  "__afl_setup_first:\n"
  "\n"
  "  /* Save caller-saved regs possibly touched by libcalls. */\n"
  "\n"
  "  lea   rsp, [rsp - 352]\n"
  "\n"
  "  mov   qword ptr [rsp + 0],  rax\n"
  "  mov   qword ptr [rsp + 8],  rcx\n"
  "  mov   qword ptr [rsp + 16], rdi\n"
  "  mov   qword ptr [rsp + 32], rsi\n"
  "  mov   qword ptr [rsp + 40], r8\n"
  "  mov   qword ptr [rsp + 48], r9\n"
  "  mov   qword ptr [rsp + 56], r10\n"
  "  mov   qword ptr [rsp + 64], r11\n"
  "\n"
  "  movdqu  xmmword ptr [rsp + 96],  xmm0\n"
  "  movdqu  xmmword ptr [rsp + 112], xmm1\n"
  "  movdqu  xmmword ptr [rsp + 128], xmm2\n"
  "  movdqu  xmmword ptr [rsp + 144], xmm3\n"
  "  movdqu  xmmword ptr [rsp + 160], xmm4\n"
  "  movdqu  xmmword ptr [rsp + 176], xmm5\n"
  "  movdqu  xmmword ptr [rsp + 192], xmm6\n"
  "  movdqu  xmmword ptr [rsp + 208], xmm7\n"
  "  movdqu  xmmword ptr [rsp + 224], xmm8\n"
  "  movdqu  xmmword ptr [rsp + 240], xmm9\n"
  "  movdqu  xmmword ptr [rsp + 256], xmm10\n"
  "  movdqu  xmmword ptr [rsp + 272], xmm11\n"
  "  movdqu  xmmword ptr [rsp + 288], xmm12\n"
  "  movdqu  xmmword ptr [rsp + 304], xmm13\n"
  "  movdqu  xmmword ptr [rsp + 320], xmm14\n"
  "  movdqu  xmmword ptr [rsp + 336], xmm15\n"
  "\n"
  "  /* 16-byte stack alignment setup. */\n"
  "\n"
  "  push  r12\n"
  "  mov   r12, rsp\n"
  "  sub   rsp, 16\n"
  "  and   rsp, -16\n"
  "\n"
  "  lea   rdi, [rip + .AFL_SHM_ENV]\n"
  CALL_L64("getenv")
  "\n"
  "  test  rax, rax\n"
  "  je    __afl_setup_abort\n"
  "\n"
#ifdef USEMMAP
  "  mov   edx, 384   /* shm_open mode 0600 */\n"
  "  mov   esi, 2     /* flags O_RDWR      */\n"
  "  mov   rdi, rax   /* SHM file path     */\n"
  CALL_L64("shm_open")
  "\n"
  "  cmp   rax, -1\n"
  "  je    __afl_setup_abort\n"
  "\n"
  "  mov   r9d, 0\n"
  "  mov   r8d, eax\n"
  "  mov   ecx, 1\n"
  "  mov   edx, 3\n"
  "  mov   esi, " STRINGIFY(MAP_SIZE) "\n"
  "  mov   edi, 0\n"
  CALL_L64("mmap")
  "\n"
  "  cmp   rax, -1\n"
  "  je    __afl_setup_abort\n"
  "\n"
#else
  "  mov   rdi, rax\n"
  CALL_L64("atoi")
  "\n"
  "  xor   rdx, rdx   /* shmat flags    */\n"
  "  xor   rsi, rsi   /* requested addr */\n"
  "  mov   rdi, rax   /* SHM ID         */\n"
  CALL_L64("shmat")
  "\n"
  "  cmp   rax, -1\n"
  "  je    __afl_setup_abort\n"
  "\n"
#endif
  "  mov   byte ptr [rax], 1\n"
  "  /* Store the address of the SHM region. */\n"
  "\n"
  "  mov   rdx, rax\n"
  "  mov   qword ptr [rip + __afl_area_ptr], rax\n"
  "\n"
  "  mov   rdx, qword ptr [rip + __afl_global_area_ptr@GOTPCREL]\n"
  "  mov   qword ptr [rdx], rax\n"
  "  mov   rdx, rax\n"
  "\n"
  "__afl_forkserver:\n"
  "\n"
  "  /* Enter fork server mode (push rdx twice for alignment). */\n"
  "\n"
  "  push  rdx\n"
  "  push  rdx\n"
  "\n"
  "  /* Tell parent we're alive. */\n"
  "\n"
  "  mov   rdx, 4                      /* length    */\n"
  "  lea   rsi, [rip + __afl_temp]     /* data      */\n"
  "  mov   rdi, " STRINGIFY((FORKSRV_FD + 1)) "        /* file desc */\n"
  CALL_L64("write")
  "\n"
  "  cmp   rax, 4\n"
  "  jne   __afl_fork_resume\n"
  "\n"
  "__afl_fork_wait_loop:\n"
  "\n"
  "  /* Wait for parent; abort if read fails. */\n"
  "\n"
  "  mov   rdx, 4\n"
  "  lea   rsi, [rip + __afl_temp]\n"
  "  mov   rdi, " STRINGIFY(FORKSRV_FD) "\n"
  CALL_L64("read")
  "  cmp   rax, 4\n"
  "  jne   __afl_die\n"
  "\n"
  "  /* Fork. */\n"
  "\n"
  CALL_L64("fork")
  "  cmp   rax, 0\n"
  "  jl    __afl_die\n"
  "  je    __afl_fork_resume\n"
  "\n"
  "  /* Parent: send child PID, wait, relay status, loop. */\n"
  "\n"
  "  mov   dword ptr [rip + __afl_fork_pid], eax\n"
  "\n"
  "  mov   rdx, 4\n"
  "  lea   rsi, [rip + __afl_fork_pid]\n"
  "  mov   rdi, " STRINGIFY((FORKSRV_FD + 1)) "\n"
  CALL_L64("write")
  "\n"
  "  mov   rdx, 0\n"
  "  lea   rsi, [rip + __afl_temp]\n"
  "  mov   rdi, qword ptr [rip + __afl_fork_pid]\n"
  CALL_L64("waitpid")
  "  cmp   rax, 0\n"
  "  jle   __afl_die\n"
  "\n"
  "  mov   rdx, 4\n"
  "  lea   rsi, [rip + __afl_temp]\n"
  "  mov   rdi, " STRINGIFY((FORKSRV_FD + 1)) "\n"
  CALL_L64("write")
  "\n"
  "  jmp   __afl_fork_wait_loop\n"
  "\n"
  "__afl_fork_resume:\n"
  "\n"
  "  /* Child: close fds, restore, resume. */\n"
  "\n"
  "  mov   rdi, " STRINGIFY(FORKSRV_FD) "\n"
  CALL_L64("close")
  "\n"
  "  mov   rdi, " STRINGIFY((FORKSRV_FD + 1)) "\n"
  CALL_L64("close")
  "\n"
  "  pop   rdx\n"
  "  pop   rdx\n"
  "\n"
  "  mov   rsp, r12\n"
  "  pop   r12\n"
  "\n"
  "  mov   rax, qword ptr [rsp + 0]\n"
  "  mov   rcx, qword ptr [rsp + 8]\n"
  "  mov   rdi, qword ptr [rsp + 16]\n"
  "  mov   rsi, qword ptr [rsp + 32]\n"
  "  mov   r8,  qword ptr [rsp + 40]\n"
  "  mov   r9,  qword ptr [rsp + 48]\n"
  "  mov   r10, qword ptr [rsp + 56]\n"
  "  mov   r11, qword ptr [rsp + 64]\n"
  "\n"
  "  movdqu  xmm0,  xmmword ptr [rsp + 96]\n"
  "  movdqu  xmm1,  xmmword ptr [rsp + 112]\n"
  "  movdqu  xmm2,  xmmword ptr [rsp + 128]\n"
  "  movdqu  xmm3,  xmmword ptr [rsp + 144]\n"
  "  movdqu  xmm4,  xmmword ptr [rsp + 160]\n"
  "  movdqu  xmm5,  xmmword ptr [rsp + 176]\n"
  "  movdqu  xmm6,  xmmword ptr [rsp + 192]\n"
  "  movdqu  xmm7,  xmmword ptr [rsp + 208]\n"
  "  movdqu  xmm8,  xmmword ptr [rsp + 224]\n"
  "  movdqu  xmm9,  xmmword ptr [rsp + 240]\n"
  "  movdqu  xmm10, xmmword ptr [rsp + 256]\n"
  "  movdqu  xmm11, xmmword ptr [rsp + 272]\n"
  "  movdqu  xmm12, xmmword ptr [rsp + 288]\n"
  "  movdqu  xmm13, xmmword ptr [rsp + 304]\n"
  "  movdqu  xmm14, xmmword ptr [rsp + 320]\n"
  "  movdqu  xmm15, xmmword ptr [rsp + 336]\n"
  "\n"
  "  lea   rsp, [rsp + 352]\n"
  "\n"
  "  jmp   __afl_store\n"
  "\n"
  "__afl_die:\n"
  "\n"
  "  xor   rax, rax\n"
  CALL_L64("_exit")
  "\n"
  "__afl_setup_abort:\n"
  "\n"
  "  /* Remember failure to avoid repeated shmat/shmget. */\n"
  "\n"
  "  inc   byte ptr [rip + __afl_setup_failure]\n"
  "\n"
  "  mov   rsp, r12\n"
  "  pop   r12\n"
  "\n"
  "  mov   rax, qword ptr [rsp + 0]\n"
  "  mov   rcx, qword ptr [rsp + 8]\n"
  "  mov   rdi, qword ptr [rsp + 16]\n"
  "  mov   rsi, qword ptr [rsp + 32]\n"
  "  mov   r8,  qword ptr [rsp + 40]\n"
  "  mov   r9,  qword ptr [rsp + 48]\n"
  "  mov   r10, qword ptr [rsp + 56]\n"
  "  mov   r11, qword ptr [rsp + 64]\n"
  "\n"
  "  movdqu  xmm0,  xmmword ptr [rsp + 96]\n"
  "  movdqu  xmm1,  xmmword ptr [rsp + 112]\n"
  "  movdqu  xmm2,  xmmword ptr [rsp + 128]\n"
  "  movdqu  xmm3,  xmmword ptr [rsp + 144]\n"
  "  movdqu  xmm4,  xmmword ptr [rsp + 160]\n"
  "  movdqu  xmm5,  xmmword ptr [rsp + 176]\n"
  "  movdqu  xmm6,  xmmword ptr [rsp + 192]\n"
  "  movdqu  xmm7,  xmmword ptr [rsp + 208]\n"
  "  movdqu  xmm8,  xmmword ptr [rsp + 224]\n"
  "  movdqu  xmm9,  xmmword ptr [rsp + 240]\n"
  "  movdqu  xmm10, xmmword ptr [rsp + 256]\n"
  "  movdqu  xmm11, xmmword ptr [rsp + 272]\n"
  "  movdqu  xmm12, xmmword ptr [rsp + 288]\n"
  "  movdqu  xmm13, xmmword ptr [rsp + 304]\n"
  "  movdqu  xmm14, xmmword ptr [rsp + 320]\n"
  "  movdqu  xmm15, xmmword ptr [rsp + 336]\n"
  "\n"
  "  lea   rsp, [rsp + 352]\n"
  "\n"
  "  jmp   __afl_return\n"
  "\n"
  ".AFL_VARS:\n"
  "\n"
  "  .lcomm   __afl_area_ptr, 8\n"
#ifndef COVERAGE_ONLY
  "  .lcomm   __afl_prev_loc, 8\n"
#endif                                                  /* !COVERAGE_ONLY */
  "  .lcomm   __afl_fork_pid, 4\n"
  "  .lcomm   __afl_temp, 4\n"
  "  .lcomm   __afl_setup_failure, 1\n"
  "\n"
  "  .comm    __afl_global_area_ptr, 8, 8\n"
  "\n"
  ".AFL_SHM_ENV:\n"
  "  .asciz \"" SHM_ENV_VAR "\"\n"
  ".intel_syntax prefix\n"
  "\n"
  "/* --- END --- */\n"
  "\n";

#endif                                                   /* !_HAVE_AFL_AS_H */
