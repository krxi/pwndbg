#!/usr/bin/env python3
"""
Generate per-architecture Linux syscall signatures from a kernel source tree.

Usage: generate-syscalls-data.py <path-to-linux-source> [--json] > pwndbg/lib/syscalls_data.py

For every supported architecture we read its syscall table (*.tbl) to get
number -> name -> entry point (e.g. `56 common clone sys_clone`), then resolve
the entry point to a `SYSCALL_DEFINEn(name, type, arg, ...)` definition.

Some syscalls have several definitions selected by the preprocessor
(e.g. `clone` with CONFIG_CLONE_BACKWARDS*), or arch-specific overrides
(e.g. `mmap` in arch/x86/kernel/sys_x86_64.c), so each definition keeps the
`#if` conditions it is nested in and is resolved per architecture.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ArchSpec:
    table: str
    abis: frozenset[str]
    archdir: str
    # Kconfig symbols that change which definition is picked.
    config: frozenset[str]


ARCHES: dict[str, ArchSpec] = {
    "x86-64": ArchSpec(
        "arch/x86/entry/syscalls/syscall_64.tbl",
        frozenset({"common", "64"}),
        "x86",
        frozenset({"X86_64", "64BIT"}),
    ),
    "i386": ArchSpec(
        "arch/x86/entry/syscalls/syscall_32.tbl",
        frozenset({"i386"}),
        "x86",
        frozenset({"X86_32", "CLONE_BACKWARDS"}),
    ),
    "aarch64": ArchSpec(
        "scripts/syscall.tbl",
        frozenset({"common", "64", "renameat", "rlimit", "memfd_secret"}),
        "arm64",
        frozenset({"64BIT", "CLONE_BACKWARDS"}),
    ),
    "arm": ArchSpec(
        "arch/arm/tools/syscall.tbl",
        frozenset({"common", "eabi"}),
        "arm",
        frozenset({"CLONE_BACKWARDS"}),
    ),
    "rv64": ArchSpec(
        "scripts/syscall.tbl",
        frozenset({"common", "64", "riscv", "rlimit", "memfd_secret"}),
        "riscv",
        frozenset({"64BIT", "CLONE_BACKWARDS"}),
    ),
    "mips": ArchSpec(
        "arch/mips/kernel/syscalls/syscall_o32.tbl",
        frozenset({"o32"}),
        "mips",
        frozenset({"CLONE_BACKWARDS"}),
    ),
    "powerpc": ArchSpec(
        "arch/powerpc/kernel/syscalls/syscall.tbl",
        frozenset({"common", "32", "nospu"}),
        "powerpc",
        frozenset({"CLONE_BACKWARDS"}),
    ),
    "s390x": ArchSpec(
        "arch/s390/kernel/syscalls/syscall.tbl",
        frozenset({"common", "64"}),
        "s390",
        frozenset({"64BIT", "CLONE_BACKWARDS2"}),
    ),
    "loongarch64": ArchSpec(
        "scripts/syscall.tbl",
        frozenset({"common", "64", "memfd_secret"}),
        "loongarch",
        frozenset({"64BIT"}),
    ),
}

# Only these symbols are evaluated; any other `#if` is treated as unknown.
KNOWN_CONFIGS = {
    "CONFIG_CLONE_BACKWARDS",
    "CONFIG_CLONE_BACKWARDS2",
    "CONFIG_CLONE_BACKWARDS3",
    "CONFIG_X86_32",
    "CONFIG_X86_64",
    "CONFIG_64BIT",
}

SKIP_DIRS = ("tools/", "Documentation/", "samples/", "scripts/", "arch/x86/um/", "arch/um/")
# Fallback definitions used only when the real subsystem is compiled out.
SKIP_FILES = {"kernel/time/posix-stubs.c"}


@dataclass(frozen=True)
class Definition:
    name: str
    args: tuple[tuple[str, str], ...]  # (type, name)
    path: str
    line: int
    conds: tuple[tuple[str, bool], ...]  # (condition, must_be_true)


def parse_table(path: Path, abis: frozenset[str]) -> list[tuple[int, str, str]]:
    rows = []
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].split()
        if len(line) < 3 or line[1] not in abis:
            continue
        nr, _abi, name = line[:3]
        entry = line[3] if len(line) > 3 else ""
        rows.append((int(nr), name, entry))
    return rows


def condition_stack(lines: list[str]) -> list[tuple[tuple[str, bool], ...]]:
    """For each line, the `#if` conditions it is nested in."""
    # Each frame: list of previous branch conditions + current branch condition.
    stack: list[list[tuple[str, bool]]] = []
    result = []
    for line in lines:
        s = line.strip()
        m = re.match(r"#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)", s)
        if m:
            kind, rest = m.group(1), m.group(2).strip()
            if kind == "ifdef":
                stack.append([(f"defined({rest})", True)])
            elif kind == "ifndef":
                stack.append([(f"defined({rest})", False)])
            elif kind == "if":
                stack.append([(rest, True)])
            elif kind == "elif" and stack:
                frame = stack[-1]
                frame[-1] = (frame[-1][0], not frame[-1][1])
                frame.append((rest, True))
            elif kind == "else" and stack:
                frame = stack[-1]
                frame[-1] = (frame[-1][0], not frame[-1][1])
            elif kind == "endif" and stack:
                stack.pop()
        result.append(tuple(c for frame in stack for c in frame))
    return result


def parse_definitions(root: Path) -> dict[str, list[Definition]]:
    defs: dict[str, list[Definition]] = {}
    pattern = re.compile(r"\bSYSCALL_DEFINE([0-6])\s*\(")
    for path in root.rglob("*.c"):
        rel = path.relative_to(root).as_posix()
        if rel.startswith(SKIP_DIRS) or rel in SKIP_FILES:
            continue
        text = path.read_text(errors="replace")
        if "SYSCALL_DEFINE" not in text:
            continue
        lines = text.splitlines()
        conds = condition_stack(lines)
        for m in pattern.finditer(text):
            # Skip the macro definitions themselves.
            line_start = text.rfind("\n", 0, m.start()) + 1
            if text[line_start : m.start()].strip().startswith("#"):
                continue
            depth, i = 1, m.end()
            while depth and i < len(text):
                depth += {"(": 1, ")": -1}.get(text[i], 0)
                i += 1
            parts = [p.strip() for p in text[m.end() : i - 1].replace("\n", " ").split(",")]
            name, flat = parts[0], parts[1:]
            if len(flat) != 2 * int(m.group(1)):
                continue
            args = tuple((" ".join(flat[j].split()), flat[j + 1]) for j in range(0, len(flat), 2))
            lineno = text.count("\n", 0, m.start())
            defs.setdefault(name, []).append(Definition(name, args, rel, lineno + 1, conds[lineno]))
    return defs


def eval_cond(cond: str, config: frozenset[str]) -> bool | None:
    symbols = re.findall(r"\bCONFIG_\w+\b|\b__ARCH_\w+\b", cond)
    if not symbols or any(s not in KNOWN_CONFIGS for s in symbols):
        return None
    expr = re.sub(r"defined\s*\(\s*(\w+)\s*\)", r"\1", cond)
    expr = expr.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    env = {s: s.removeprefix("CONFIG_") in config for s in symbols}
    try:
        return bool(eval(expr, {"__builtins__": {}}, env))
    except SyntaxError:
        return None


def resolve(cands: list[Definition], spec: ArchSpec) -> tuple[Definition | None, str]:
    def score(d: Definition) -> tuple[int, int] | None:
        unknown = 0
        for cond, want in d.conds:
            val = eval_cond(cond, spec.config)
            if val is None:
                unknown += 1
            elif val != want:
                return None
        in_arch = d.path.startswith(f"arch/{spec.archdir}/")
        other_arch = d.path.startswith("arch/") and not in_arch
        if other_arch:
            return None
        return (0 if in_arch else 1, unknown)

    scored = sorted(((s, d) for d in cands if (s := score(d)) is not None), key=lambda sd: sd[0])
    if not scored:
        return None, "no matching definition"
    best = [d for s, d in scored if s == scored[0][0]]
    if len({d.args for d in best}) > 1:
        return best[0], "ambiguous: " + ", ".join(f"{d.path}:{d.line}" for d in best)
    return best[0], ""


def normalize_type(ctype: str) -> tuple[str, int]:
    """`const char __user *const __user *` -> ("char", 2), like functions_data.py."""
    derefcnt = ctype.count("*")
    words = [
        w
        for w in ctype.replace("*", " ").split()
        if w not in ("const", "volatile", "__user", "struct", "union", "enum")
    ]
    return " ".join(words), derefcnt


HEADER = '''"""
Linux syscall signatures, per architecture.

Generated by scripts/generate-syscalls-data.py from Linux {version}. Do not edit by hand.
"""

from __future__ import annotations

# arch -> syscall name -> ((type, derefcnt, name), ...)
SYSCALLS: dict[str, dict[str, tuple[tuple[str, int, str], ...]]] = {{
'''


def write_python(out: dict[str, dict[str, dict[str, Any]]], version: str) -> str:
    lines = [HEADER.format(version=version)]
    for arch, calls in out.items():
        lines.append(f"    {arch!r}: {{\n")
        for name, info in sorted(calls.items()):
            args = tuple((*normalize_type(t), n) for t, n in info["args"])
            lines.append(f"        {name!r}: {args!r},\n")
        lines.append("    },\n")
    lines.append("}\n")
    return "".join(lines)


def main() -> None:
    root = Path(sys.argv[1])
    defs = parse_definitions(root)
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for arch, spec in ARCHES.items():
        table = parse_table(root / spec.table, spec.abis)
        out[arch] = {}
        missing, ambiguous = [], []
        for nr, name, entry in table:
            if not entry or entry == "sys_ni_syscall":
                continue
            sym = re.sub(r"^(__\w+?_)?sys_", "", entry)
            d, note = resolve(defs.get(sym, []), spec)
            if d is None:
                missing.append(f"{name}({entry})")
                continue
            if note:
                ambiguous.append(f"{name}: {note}")
            out[arch][name] = {
                "nr": nr,
                "args": [list(a) for a in d.args],
                "source": f"{d.path}:{d.line}",
            }
        print(
            f"{arch:12} resolved={len(out[arch]):4} missing={len(missing):3} "
            f"ambiguous={len(ambiguous)}",
            file=sys.stderr,
        )
        for line in missing[:8] + ambiguous[:5]:
            print(f"    {line}", file=sys.stderr)
    if "--json" in sys.argv:
        json.dump(out, sys.stdout, indent=1)
    else:
        version = (root / "Makefile").read_text()
        v = dict(re.findall(r"^(VERSION|PATCHLEVEL|SUBLEVEL) = (\d+)", version, re.MULTILINE))
        sys.stdout.write(write_python(out, f"{v['VERSION']}.{v['PATCHLEVEL']}.{v['SUBLEVEL']}"))


if __name__ == "__main__":
    main()
