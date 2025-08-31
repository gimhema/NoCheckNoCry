#!/usr/bin/env python3
# who_the_null.py  —  "WhoTheNull?" project-wide nullptr guard checker
# Python 3.12+

from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

# ---------- File filters ----------
DEFAULT_EXTS = {".h", ".hpp", ".hh", ".hxx", ".c", ".cc", ".cpp", ".cxx"}

# ---------- Regexes (intentionally simple/robust-ish) ----------
# T* var;
RE_PTR_DECL = re.compile(r"""
    \b
    ([\w:<>]+        # type (rough)
      (?:\s+const)?  # optional trailing const
    )
    \s* \* \s*
    (\w+)            # var name
    \s* (?:[=][^;]*)?
    ;
""", re.VERBOSE)

# class/struct block start/end
RE_CLASS_START = re.compile(r'\b(class|struct)\b\s+\w+[^;{]*{')
RE_BLOCK_OPEN  = re.compile(r'{')
RE_BLOCK_CLOSE = re.compile(r'}')

# if (p), if(p != nullptr), if(nullptr != p), if(p && p->m), if(p && p->m && p->m->k) ...
RE_IF_LINE = re.compile(r'\bif\s*\((.*?)\)\s*{?')

# var->member usage
RE_ARROW_USE = re.compile(r'(\w+)\s*->\s*(\w+)')

# simple obj && obj->m guard pattern(s)
RE_GUARD_PAIR_1 = re.compile(r'\b(\w+)\s*&&\s*\1\s*->\s*(\w+)')
RE_GUARD_PAIR_NOTNULL = re.compile(r'\b(\w+)\s*!=\s*nullptr\s*&&\s*\1\s*->\s*(\w+)')

# single var null-checks inside if
RE_VAR_POSITIVE = re.compile(r'\b(\w+)\b\s*(?:!=\s*nullptr)?\b')
RE_VAR_NOTNULL  = re.compile(r'\b(\w+)\s*!=\s*nullptr\b')
RE_VAR_NONNULL_PREFIX = re.compile(r'\bnullptr\s*!=\s*(\w+)\b')

# early return guard: if(!p) return ...;
RE_EARLY_RETURN = re.compile(r'\bif\s*\(\s*!\s*(\w+)\s*\)\s*return\b')

# guard macros like ASSERT(p), CHECK(p), ENSURE(p), etc. (configurable)
def build_guard_macro_regex(macros: List[str]) -> re.Pattern:
    # match MAC(p) or MAC(p != nullptr)
    inner = "|".join(re.escape(m) for m in macros)
    return re.compile(r'\b(?:' + inner + r')\s*\(\s*([^)]+)\)')

# strip comments (/* */ and //) – very naive but enough for our heuristic
RE_LINE_COMMENT = re.compile(r'//.*')
RE_BLOCK_COMMENT_OPEN = re.compile(r'/\*')
RE_BLOCK_COMMENT_CLOSE = re.compile(r'\*/')


def should_scan(path: Path, excludes: Set[str]) -> bool:
    if path.suffix.lower() in DEFAULT_EXTS:
        # check excluded dirs anywhere in path parts
        for part in path.parts:
            if part in excludes:
                return False
        return True
    return False


def strip_comments(src: str) -> str:
    # remove block comments (naive, multi-line)
    out = []
    i, n = 0, len(src)
    in_block = False
    while i < n:
        if not in_block:
            m = RE_BLOCK_COMMENT_OPEN.search(src, i)
            if not m:
                out.append(src[i:])
                break
            out.append(src[i:m.start()])
            i = m.end()
            in_block = True
        else:
            m = RE_BLOCK_COMMENT_CLOSE.search(src, i)
            if not m:
                # unclosed, drop rest
                break
            i = m.end()
            in_block = False
    text = "".join(out)
    # remove // comments line-by-line
    text = "\n".join(RE_LINE_COMMENT.sub("", line) for line in text.splitlines())
    return text


def collect_member_ptr_names(text: str) -> Set[str]:
    """
    Very rough: inside class/struct blocks, gather pointer member names: T* m_ptr;
    We only keep the 'name' (m_ptr), not the owner type.
    """
    names: Set[str] = set()
    depth = 0
    for line in text.splitlines():
        if RE_CLASS_START.search(line):
            depth += 1
        else:
            # track generic braces to decide "in-class" region
            if RE_BLOCK_OPEN.search(line):
                depth += 1
            if RE_BLOCK_CLOSE.search(line):
                depth = max(0, depth - 1)

        if depth > 0:
            for m in RE_PTR_DECL.finditer(line):
                var = m.group(2)
                names.add(var)
    return names


def tokenize_braces(line: str) -> Tuple[int, int]:
    """count '{' and '}' occurrences on a line"""
    return line.count('{'), line.count('}')


def analyze_file(path: Path, guard_macros: List[str]) -> List[Tuple[int, str]]:
    """
    Returns list of (line_no, message) warnings for a file.
    """
    src = path.read_text(encoding="utf-8", errors="ignore")
    src_nc = strip_comments(src)
    lines = src_nc.splitlines()

    guard_macro_re = build_guard_macro_regex(guard_macros + ["assert", "ASSERT"])

    # Collect simple pointer variable declarations (non-member; but we'll still
    # collect everywhere as a heuristic)
    pointer_vars: Dict[str, int] = {}  # var -> decl line

    # Collect member pointer names (from class/struct regions)
    member_ptr_names = collect_member_ptr_names(src_nc)

    warnings: List[Tuple[int, str]] = []

    # guard stack: list of sets — each scope has a set of guarded keys
    # keys can be: 'p' for variable pointer, or 'obj.member' for member pointer
    guard_stack: List[Set[str]] = [set()]
    early_guard: Set[str] = set()  # variables guarded by if(!p) return; (function-scope persistent)

    def current_guards() -> Set[str]:
        # union of all scopes + early_guard
        s: Set[str] = set(early_guard)
        for g in guard_stack:
            s |= g
        return s

    for i, line in enumerate(lines, start=1):
        opened, closed = tokenize_braces(line)
        # pointer declarations
        for m in RE_PTR_DECL.finditer(line):
            var = m.group(2)
            # avoid capturing common keywords that can look like names
            if var not in ("operator",):
                pointer_vars.setdefault(var, i)

        # early return guard
        m_er = RE_EARLY_RETURN.search(line)
        if m_er:
            early_guard.add(m_er.group(1))

        # guard macros: ASSERT(p), CHECK(p), ...
        for m in guard_macro_re.finditer(line):
            inner = m.group(1)
            # pick simple names and pairs like "obj->m_ptr"
            for v in re.findall(r'\b(\w+)\b', inner):
                if v in pointer_vars:
                    guard_stack[-1].add(v)
            for mm in RE_ARROW_USE.finditer(inner):
                base, mem = mm.group(1), mm.group(2)
                guard_stack[-1].add(f"{base}.{mem}")

        # IF-guards
        m_if = RE_IF_LINE.search(line)
        if m_if:
            cond = m_if.group(1)

            new_guards: Set[str] = set()

            # obj && obj->mem
            for m in RE_GUARD_PAIR_1.finditer(cond):
                base, mem = m.group(1), m.group(2)
                new_guards.add(base)
                new_guards.add(f"{base}.{mem}")

            # obj != nullptr && obj->mem
            for m in RE_GUARD_PAIR_NOTNULL.finditer(cond):
                base, mem = m.group(1), m.group(2)
                new_guards.add(base)
                new_guards.add(f"{base}.{mem}")

            # singular var positive checks
            for m in RE_VAR_NOTNULL.finditer(cond):
                new_guards.add(m.group(1))
            for m in RE_VAR_NONNULL_PREFIX.finditer(cond):
                new_guards.add(m.group(1))

            # bare if(p) — treat as guarded
            # (but don't greedily add everything; only pointer vars we know)
            for m in RE_VAR_POSITIVE.finditer(cond):
                v = m.group(1)
                if v in pointer_vars:
                    new_guards.add(v)

            # on encountering IF, if it opens a block on the same line, push once
            if opened == 0:
                # push guard set so that if body starts on next line with '{', we still have it; keep it at top level
                guard_stack.append(set(new_guards))
            else:
                # already opened — apply for this new scope
                guard_stack.append(set(new_guards))
                opened -= 1  # one '{' consumed by the if

        # handle remaining '{'
        for _ in range(opened):
            guard_stack.append(set())

        # detect arrow uses on this line
        for m in RE_ARROW_USE.finditer(line):
            base, member = m.group(1), m.group(2)
            key_member = f"{base}.{member}"

            guards_now = current_guards()

            # Case A: direct pointer variable use: p->...
            direct_ptr_issue = (
                base in pointer_vars and base not in guards_now
            )

            # Case B: member pointer use: obj->m_ptr->...
            member_ptr_issue = (
                member in member_ptr_names and key_member not in guards_now
            )

            if direct_ptr_issue:
                decl_line = pointer_vars.get(base, '?')
                warnings.append((
                    i,
                    f"[UNGUARDED] '{base}->...' at line {i} "
                    f"(declared at line {decl_line}) without NULL guard."
                ))

            if member_ptr_issue:
                # we can give a hint about typical guard
                warnings.append((
                    i,
                    f"[UNGUARDED MEMBER] '{base}->{member}->...' at line {i} "
                    f"without guard like 'if ({base} && {base}->{member}) {{ ... }}'."
                ))

        # handle closing braces
        for _ in range(closed):
            if guard_stack:
                guard_stack.pop()
        if not guard_stack:
            guard_stack.append(set())  # never empty to simplify

    return warnings


def main() -> int:
    ap = argparse.ArgumentParser(
        description="WhoTheNull? — project-wide nullptr guard checker for raw pointers."
    )
    ap.add_argument("root", type=str, help="Project root directory")
    ap.add_argument("--exclude", nargs="*", default=[".git", "build", "out", "dist"],
                    help="Directory names to exclude")
    ap.add_argument("--guard-macros", nargs="*", default=[],
                    help="Extra guard macro names (e.g., CHECK ENSURE VERIFY MY_ASSERT)")
    ap.add_argument("--ext", nargs="*", default=[],
                    help="Extra file extensions to include (e.g., .ino .tpp)")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    ex_dirs = set(args.exclude)
    if args.ext:
        for e in args.ext:
            DEFAULT_EXTS.add(e if e.startswith('.') else f".{e}")

    findings: List[Tuple[Path, int, str]] = []

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if should_scan(p, ex_dirs):
            warnings = analyze_file(p, args.guard_macros)
            for line_no, msg in warnings:
                findings.append((p, line_no, msg))

    if findings:
        for f, ln, msg in sorted(findings):
            print(f"{f}:{ln}: {msg}")
        return 1

    print("WhoTheNull? clean: no unguarded pointer member access found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
