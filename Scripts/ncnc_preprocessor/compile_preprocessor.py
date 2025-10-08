#!/usr/bin/env python3
# compile_preprocessor.py
# Heuristic, compiler-agnostic static checks for C/C++ projects.
import sys, os, re, io, pathlib, collections, argparse

SRC_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"}
INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"')
FUNC_SIG_RE = re.compile(r'''(^|\s)(?:template\s*<[^>]*>\s*)?
    (?:[\w:\~\<\>\*&\s]+?)        # return + qualifiers
    \s+([\w:~]+)\s*               # name
    \(\s*([^\)]*)\s*\)\s*         # (params)
    (?:const\b|noexcept\b|override\b|final\b|\s)*\{''', re.X)
PTR_PARAM_RE = re.compile(r'(?:^|[,]\s*)(?:[\w:<>]+\s*(?:\*+|&)\s*)(\w+)')
VAR_DECL_RE = re.compile(r'(?:^|\s)(?:[\w:<>]+\s*(?:\*+|&)?\s+)(\w+)\s*(?:[=;,\)])')
DELETE_RE = re.compile(r'\bdelete\s*(\[\s*\])?\s*(\w+)')
ARROW_RE = re.compile(r'(\w+)\s*->')
GUARD_HINTS = (
    re.compile(r'\bif\s*\(\s*(!\s*)?([A-Za-z_]\w*)\s*\)'),
    re.compile(r'\bif\s*\(\s*([A-Za-z_]\w*)\s*!=\s*nullptr\s*\)'),
    re.compile(r'\bassert\s*\(\s*([A-Za-z_]\w*)\s*\)'),
    re.compile(r'\bExpects\s*\(\s*([A-Za-z_]\w*)\s*(!=nullptr)?\s*\)'),
)
THIS_ASSIGN_ADDR_RE = re.compile(r'\bthis->\s*\w+\s*=\s*&\s*([A-Za-z_]\w*)\b')
GLOBAL_ASSIGN_ADDR_RE = re.compile(r'\b(?:[A-Za-z_]\w*::)*[A-Za-z_]\w+\s*=\s*&\s*([A-Za-z_]\w*)\b')

Issue = collections.namedtuple("Issue", "tag file line col msg snippet")

def iter_files(root, exclude_patterns):
    def excluded(p: pathlib.Path) -> bool:
        s = str(p.as_posix())
        return any(x in s for x in exclude_patterns)
    for p in pathlib.Path(root).rglob("*"):
        if p.is_file() and p.suffix.lower() in SRC_EXT and not excluded(p):
            yield p

def read_text(path):
    try:
        return pathlib.Path(path).read_text(encoding="utf-8")
    except Exception:
        try:
            return pathlib.Path(path).read_text(encoding="cp949")
        except Exception:
            return ""

def build_include_graph(root, exclude_patterns):
    graph = collections.defaultdict(set)
    path_index = {}
    for p in iter_files(root, exclude_patterns):
        path_index[p.name] = p
    for p in iter_files(root, exclude_patterns):
        txt = read_text(p)
        for i, line in enumerate(txt.splitlines(), 1):
            m = INCLUDE_RE.match(line)
            if not m: continue
            inc = m.group(1)
            cand = None
            rel = (p.parent / inc).resolve()
            if rel.exists(): cand = rel
            elif inc in path_index: cand = path_index[inc]
            if cand:
                graph[str(p.resolve())].add(str(cand.resolve()))
    return graph

def find_include_cycles(graph):
    visited, stack = set(), set()
    cycles = []
    def dfs(u, path):
        visited.add(u); stack.add(u)
        for v in graph.get(u, ()):
            if v not in visited:
                dfs(v, path + [v])
            elif v in stack:
                if v in path:
                    i = path.index(v)
                    cyc = path[i:] + [v]
                else:
                    cyc = [v, u, v]
                cycles.append(cyc)
        stack.remove(u)
    for node in list(graph.keys()):
        if node not in visited:
            dfs(node, [node])
    seen = set(); out = []
    for cyc in cycles:
        key = tuple(sorted(cyc))
        if key not in seen:
            seen.add(key); out.append(cyc)
    return out

def split_functions(text):
    funcs = []
    lines = text.splitlines()
    joined = "\n".join(lines)
    for m in FUNC_SIG_RE.finditer(joined):
        brace_pos = joined.find("{", m.end()-1)
        if brace_pos == -1: continue
        depth = 0; i = brace_pos; end = None
        while i < len(joined):
            ch = joined[i]
            if ch == '{': depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1; break
            i += 1
        if end:
            pre = joined[:brace_pos]
            start_line = pre.count("\n") + 1
            funcs.append((start_line, joined[m.start(): end ]))
    return funcs

def collect_local_vars(func_text):
    body = func_text[func_text.find('{')+1: func_text.rfind('}')]
    locals_set = set()
    for line in body.splitlines():
        code = line.split("//",1)[0]
        for m in VAR_DECL_RE.finditer(code):
            locals_set.add(m.group(1))
    return locals_set

def extract_params(func_text):
    sig = func_text[:func_text.find('{')]
    params = []
    for m in PTR_PARAM_RE.finditer(sig):
        params.append(m.group(1))
    return params

def scan_guards(window_lines):
    guards = set()
    for l in window_lines:
        s = l.split("//",1)[0]
        for rx in GUARD_HINTS:
            gm = rx.search(s)
            if gm:
                for g in gm.groups()[::-1]:
                    if g and g != 'nullptr' and g != '!':
                        if re.match(r'[A-Za-z_]\w*', g):
                            guards.add(g)
                            break
    return guards

def analyze_file(path, issues, lookback):
    txt = read_text(path)
    if not txt: return
    funcs = split_functions(txt)
    for f_start_line, ftxt in funcs:
        locals_set = collect_local_vars(ftxt)
        params = extract_params(ftxt)
        body = ftxt[ftxt.find('{')+1: ftxt.rfind('}')]
        body_lines = body.splitlines()
        for idx, raw in enumerate(body_lines):
            line = raw.split("//",1)[0]
            ln = f_start_line + idx + 1
            dm = DELETE_RE.search(line)
            if dm:
                issues.append(Issue("RAW-DELETE", path, ln, dm.start()+1,
                    "Avoid raw 'delete'/'delete[]' — prefer RAII (unique_ptr/shared_ptr) or custom deleter.",
                    raw.strip()))
            for am in ARROW_RE.finditer(line):
                var = am.group(1)
                start = max(0, idx - lookback)
                guards = scan_guards(body_lines[start:idx+1])
                if var not in guards:
                    issues.append(Issue("NULL-DEREF", path, ln, am.start(1)+1,
                        f"Pointer '{var}' may be dereferenced without a preceding null-check in nearby scope.",
                        raw.strip()))
                if var in params and var not in guards:
                    issues.append(Issue("PARAM-RAW-NOCHECK", path, ln, am.start(1)+1,
                        f"Raw pointer parameter '{var}' used via '->' without visible guard.",
                        raw.strip()))
            m1 = THIS_ASSIGN_ADDR_RE.search(line)
            if m1:
                v = m1.group(1)
                if v in locals_set:
                    issues.append(Issue("ADDR-ESCAPE", path, ln, m1.start(1)+1,
                        f"Taking address of local '{v}' and storing to member — lifetime risk.",
                        raw.strip()))
            m2 = GLOBAL_ASSIGN_ADDR_RE.search(line)
            if m2:
                v = m2.group(1)
                if v in locals_set:
                    issues.append(Issue("ADDR-ESCAPE", path, ln, m2.start(1)+1,
                        f"Taking address of local '{v}' and storing globally — lifetime risk.",
                        raw.strip()))

def print_report(root, issues, cycles, mode):
    total = len(issues) + len(cycles)
    root = os.path.abspath(root)

    def rel(p): 
        try: return os.path.relpath(p, root)
        except: return p

    if mode == "FREE":
        print(f"[FREE] issues={total} (code={len(issues)}, include_cycles={len(cycles)})")
        return 0  # never fail build

    # WARNING / ABORT -> verbose details
    print(f"[{mode}] Summary: total={total}, code={len(issues)}, include_cycles={len(cycles)}")
    if cycles:
        print("== Include Cycles ==")
        for cyc in cycles:
            chain = " -> ".join(rel(x) for x in cyc)
            print(f"  [INCLUDE-CYCLE] {chain}")
        print()

    if issues:
        print("== Issues ==")
        for it in issues:
            print(f"{rel(it.file)}:{it.line}:{it.col}: [{it.tag}] {it.msg}")
            if it.snippet:
                print(f"    {it.snippet}")

    # WARNING never fails, ABORT fails if there are problems
    if mode == "WARNING":
        return 0
    if mode == "ABORT":
        return 1 if total > 0 else 0
    # Fallback safe
    return 0

def main():
    ap = argparse.ArgumentParser(description="Heuristic, compiler-agnostic static checks for C/C++ projects.")
    ap.add_argument("project_dir", help="Project root directory")
    ap.add_argument("--mode", choices=["FREE","WARNING","ABORT"], default="WARNING",
                    help="FREE: print counts only, never fail; WARNING: details, never fail; ABORT: details, fail on issues.")
    ap.add_argument("--lookback", type=int, default=6, help="Lines to look back for null guards (default: 6)")
    ap.add_argument("--exclude", action="append", default=[],
                    help="Substring pattern to exclude (can repeat). Example: --exclude third_party --exclude build")
    args = ap.parse_args()

    root = os.path.abspath(args.project_dir)
    if not os.path.isdir(root):
        print(f"Not a directory: {root}", file=sys.stderr)
        sys.exit(2)

    # 1) include graph + cycles
    graph = build_include_graph(root, args.exclude)
    cycles = find_include_cycles(graph)

    # 2) per-file analysis
    issues = []
    for p in iter_files(root, args.exclude):
        try:
            analyze_file(str(p), issues, args.lookback)
        except Exception as e:
            print(f"[warn] failed to analyze {p}: {e}", file=sys.stderr)

    code = print_report(root, issues, cycles, args.mode)
    sys.exit(code)

if __name__ == "__main__":
    main()
