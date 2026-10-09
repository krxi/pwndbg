global _start

; Syscalls whose arguments must be annotated from the kernel's signature,
; not from a glibc wrapper: https://github.com/pwndbg/pwndbg/issues/3014

_start:
; clone(flags=SIGCHLD, newsp=0, parent_tid=0, child_tid=0, tls=0)
; The glibc wrapper is clone(fn, child_stack, flags, arg, ...).
mov eax, 56
mov edi, 0x11
xor esi, esi
xor edx, edx
xor r10d, r10d
xor r8d, r8d
clone_label:
syscall

; exit_group(7) has no glibc wrapper of that name.
mov eax, 231
mov edi, 7
exit_group_label:
syscall
