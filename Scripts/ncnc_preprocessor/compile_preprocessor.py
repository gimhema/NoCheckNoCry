#!/usr/bin/env python3
# compile_preprocessor.py
# Heuristic, compiler-agnostic static checks for C/C++ projects.
import sys, os, re, io, pathlib, collections

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

def iter_files(root):
    for p in pathlib.Path(root).rglob("*"):
        if p.is_file() and p.suffix.lower() in SRC_EXT:
            yield p

def read_text(path):
    try:
        return pathlib.Path(path).read_text(encoding="utf-8")
    except Exception:
        try:
            return pathlib.Path(path).read_text(encoding="cp949")
        except Exception:
            return ""

def build_include_graph(root):
    graph = collections.defaultdict(set)
    path_index = {}
    for p in iter_files(root):
        path_index[p.name] = p
    for p in iter_files(root):
        txt = read_text(p)
        for i, line in enumerate(txt.splitlines(), 1):
            m = INCLUDE_RE.match(line)
            if not m: continue
            inc = m.group(1)
            # resolve include if exists in tree
            cand = None
            # try relative to current dir
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
                # cycle detected; extract cycle segment
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
    # dedup by normalized tuple
    seen = set(); out = []
    for cyc in cycles:
        key = tuple(sorted(cyc))
        if key not in seen:
            seen.add(key); out.append(cyc)
    return out

def split_functions(text):
    # Very heuristic: find signatures that end with '{' and then match braces to the end.
    funcs = []
    lines = text.splitlines()
    joined = "\n".join(lines)
    for m in FUNC_SIG_RE.finditer(joined):
        start = m.start()
        # find opening brace
        brace_pos = joined.find("{", m.end()-1)
        if brace_pos == -1: continue
        # scan braces
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
            # compute line/col
            pre = joined[:brace_pos]
            start_line = pre.count("\n") + 1
            funcs.append((start_line, joined[ m.start(): end ]))
    return funcs

def collect_local_vars(func_text):
    # naive: collect simple local names after first '{'
    body = func_text[func_text.find('{')+1: func_text.rfind('}')]
    locals_set = set()
    for line in body.splitlines():
        # strip comments
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
                # last capturing group with variable
                for g in gm.groups()[::-1]:
                    if g and g != 'nullptr' and g != '!':
                        if re.match(r'[A-Za-z_]\w*', g):
                            guards.add(g)
                            break
    return guards

def analyze_file(path, issues):
    txt = read_text(path)
    if not txt: return
    # function-wise scan
    funcs = split_functions(txt)
    lines = txt.splitlines()

    for f_start_line, ftxt in funcs:
        locals_set = collect_local_vars(ftxt)
        params = extract_params(ftxt)
        body = ftxt[ftxt.find('{')+1: ftxt.rfind('}')]
        body_lines = body.splitlines()

        # sliding window for guards (lookback 6 lines by default)
        lookback = 6
        for idx, raw in enumerate(body_lines):
            line = raw.split("//",1)[0]
            ln = f_start_line + idx + 1
            # --- rule: RAW-DELETE
            dm = DELETE_RE.search(line)
            if dm:
                col = dm.start()+1
                issues.append(Issue("RAW-DELETE", path, ln, col,
                    "Avoid raw 'delete'/'delete[]' — prefer RAII (unique_ptr/shared_ptr) or custom deleter.",
                    raw.strip()))
            # --- rule: NULL-DEREF + PARAM-RAW-NOCHECK
            for am in ARROW_RE.finditer(line):
                var = am.group(1)
                # gather guards in window
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
            # --- rule: ADDR-ESCAPE (this->... = &local)
            m1 = THIS_ASSIGN_ADDR_RE.search(line)
            if m1:
                v = m1.group(1)
                if v in locals_set:
                    issues.append(Issue("ADDR-ESCAPE", path, ln, m1.start(1)+1,
                        f"Taking address of local '{v}' and storing to member — lifetime risk.",
                        raw.strip()))
            # --- rule: ADDR-ESCAPE global/static (very heuristic)
            m2 = GLOBAL_ASSIGN_ADDR_RE.search(line)
            if m2:
                v = m2.group(1)
                if v in locals_set:
                    issues.append(Issue("ADDR-ESCAPE", path, ln, m2.start(1)+1,
                        f"Taking address of local '{v}' and storing globally — lifetime risk.",
                        raw.strip()))

def main():
    if len(sys.argv) != 2:
        print("Usage: python compile_preprocessor.py <PROJECT_DIRECTORY>", file=sys.stderr)
        sys.exit(2)
    root = os.path.abspath(sys.argv[1])
    if not os.path.isdir(root):
        print(f"Not a directory: {root}", file=sys.stderr)
        sys.exit(2)

    # 1) include graph + cycle check
    graph = build_include_graph(root)
    cycles = find_include_cycles(graph)

    issues = []
    for p in iter_files(root):
        try:
            analyze_file(str(p), issues)
        except Exception as e:
            print(f"[warn] failed to analyze {p}: {e}", file=sys.stderr)

    # print report
    if cycles:
        print("== Include Cycles ==")
        for cyc in cycles:
            print("  [INCLUDE-CYCLE] " + " -> ".join(cyc))
        print()

    if issues:
        print("== Issues ==")
        for it in issues:
            rel = os.path.relpath(it.file, root)
            print(f"{rel}:{it.line}:{it.col}: [{it.tag}] {it.msg}")
            if it.snippet:
                print(f"    {it.snippet}")
        sys.exit(1 if issues else 0)
    else:
        print("[ok] no issues found")
        sys.exit(0)

if __name__ == "__main__":
    main()
