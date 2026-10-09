from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

SYSCALLS_KERNEL_ARGS_BINARY = get_binary("syscalls_kernel_args.x86-64.out")


def _syscall_args(lines: list[str]) -> list[str]:
    idx = next(i for i, line in enumerate(lines) if "►" in line)
    args = []
    for line in lines[idx + 1 :]:
        if ":" not in line or "0x" in line.split(":")[0]:
            break
        args.append(" ".join(line.split()))
    return args


@pwndbg_test
async def test_syscall_args_use_kernel_signature(ctrl: Controller) -> None:
    import pwndbg.commands.context

    await launch_to(ctrl, SYSCALLS_KERNEL_ARGS_BINARY, "clone_label")
    out = pwndbg.commands.context.context_disasm()
    assert _syscall_args(out) == [
        "clone_flags: 0x11",
        "newsp: 0",
        "parent_tidptr: 0",
        "child_tidptr: 0",
        "tls: 0",
    ]


@pwndbg_test
async def test_syscall_args_without_libc_wrapper(ctrl: Controller) -> None:
    import pwndbg.commands.context

    await launch_to(ctrl, SYSCALLS_KERNEL_ARGS_BINARY, "exit_group_label")
    out = pwndbg.commands.context.context_disasm()
    assert _syscall_args(out) == ["error_code: 7"]
