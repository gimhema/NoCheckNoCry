
#!/usr/bin/env python3
# concurrency_preprocessor.py
# Heuristic, compiler-agnostic concurrency checks for C/C++ projects.
# Modes: FREE (counts only), WARNING (details, never fail), ABORT (details, fail on issues)
import sys, os, re, pathlib, collections, argparse

SRC_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"}

# ----------------------------
# Comment annotations (optional)
# ----------------------------
#   //@guarded_by(M)    : member/global variable must be accessed under mutex/critical M
#   //@shared           : this variable is shared across threads (should be atomic or guarded)
#   //@atomic_ok        : acknowledge shared-but-non-atomic (suppresses ATOMIC-MISSING)
#   //@locks(M)         : function acquires mutex M (not used yet; reserved for future)
#
# Patterns we detect (heuristics):
#   LOCK-NOGUARD        : access to //@guarded_by(M) variable without M being held
#   LOCK-ORDER          : potential deadlock (A->B somewhere, B->A elsewhere)
#   LOCK-MISMATCH       : .lock() without matching .unlock() in same function (prefer RAII)
#   CV-WAIT-NO-PRED     : condition_variable wait not wrapped by while-predicate loop
#   ATOMIC-MISSING      : //@shared variable is non-atomic and not //@atomic_ok
#   VOLATILE-SYNC       : volatile used for synchronization
#   LONG-CRITICAL-LOOP  : infinite loop while a mutex is held
#   LONG-CRITICAL-BLOCK : blocking call while a mutex is held
#   LONG-CRITICAL-BUDGET: mutex held for more than N source lines (default 50)
#
# Notes:
# - This is a lightweight regex/brace-heuristic checker (no full C++ parsing).
# - False positives/negatives are possible; tune with --exclude and code annotations.

Issue = collections.namedtuple("Issue", "tag file line col msg snippet")

# ------------ Regexes ------------
DECL_GUARDED_RE    = re.compile(r'(?P<type>[\w:<>]+\s*(?:\*|&)?\s+)(?P<name>[A-Za-z_]\w*)\s*(?:[=;].*?)?//@guarded_by\((?P<mtx>[A-Za-z_]\w*)\)')
DECL_SHARED_RE     = re.compile(r'(?P<full>.*?\b(?P<type>std::atomic<[^>]+>|volatile|[\w:<>]+)\s+(?P<name>[A-Za-z_]\w*)\s*(?:[=;].*?)?)\s*//@shared\b')
DECL_ATOMIC_RE     = re.compile(r'\bstd::atomic\s*<[^>]+>\b')
VOLATILE_RE        = re.compile(r'\bvolatile\b')

# RAII lock patterns
RAII_LOCK_GUARD_RE = re.compile(r'\bstd::lock_guard\s*<[^>]*>\s+[A-Za-z_]\w*\s*\(\s*([A-Za-z_]\w*)\s*\)')
UNIQUE_LOCK_RE     = re.compile(r'\bstd::unique_lock\s*<[^>]*>\s+[A-Za-z_]\w*\s*\(\s*([A-Za-z_]\w*)')
SCOPED_LOCK_RE     = re.compile(r'\bstd::scoped_lock\s*(?:<[^>]*>)?\s+[A-Za-z_]\w*\s*\(\s*([^)]+)\)')  # m1, m2, ...
FSCOPELOCK_RE      = re.compile(r'\bFScopeLock\s+[A-Za-z_]\w*\s*\(\s*&?\s*([A-Za-z_]\w*)\s*\)')       # Unreal-style

# Raw lock/unlock
LOCK_CALL_RE       = re.compile(r'\b([A-Za-z_]\w*)\s*\.\s*lock\s*\(')
UNLOCK_CALL_RE     = re.compile(r'\b([A-Za-z_]\w*)\s*\.\s*unlock\s*\(')

# Guarded variable use (read/write) – very heuristic:
ASSIGN_USE_RE_TMPL = r'(?<![\w:])(?:this->)?{name}\b\s*([+\-*/%&|^]?=|[\+\-]{2})'
READ_USE_RE_TMPL   = r'(?<![\w:])(?:this->)?{name}\b(?!\s*[:(])'   # not a label or function call name

# Condition variable waits
CV_WAIT_RE         = re.compile(r'\b([A-Za-z_]\w*)\s*\.\s*(wait|wait_for|wait_until)\s*\(')

# Function splitting (heuristic)
FUNC_SIG_RE = re.compile(r'''(^|\s)(?:template\s*<[^>]*>\s*)?
    (?:[\w:\~\<\>\*&\s]+?)        # return + qualifiers
    \s+([\w:~]+)\s*               # name
    \(\s*([^\)]*)\s*\)\s*         # (params)
    (?:const\b|noexcept\b|override\b|final\b|\s)*\{''', re.X)

# NEW: Long critical section heuristics
INFINITE_LOOP_RE  = re.compile(r'\bfor\s*\(\s*;\s*;\s*\)|\bwhile\s*\(\s*true\s*\)|\bwhile\s*\(\s*1\s*\)')
BLOCKING_CALL_RE  = re.compile(
    r'\b('
    r'std::this_thread::sleep_for|sleep|Sleep|usleep|nanosleep|'
    r'(?:pthread_)?join|Join|'
    r'accept|recv|read|select|poll|'
    r'WaitForSingleObject|WaitForMultipleObjects'
    r')\s*\('
)

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

def split_functions(text):
    funcs = []
    joined = text
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

def build_guarded_map(text):
    mapping = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = DECL_GUARDED_RE.search(line)
        if m:
            mapping[m.group('name')] = (m.group('mtx'), i, line.strip())
    return mapping

def find_shared_decls(text):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = DECL_SHARED_RE.search(line)
        if not m:
            continue
        name = m.group('name')
        full = m.group('full')
        is_atomic = bool(DECL_ATOMIC_RE.search(full))
        is_volatile = bool(VOLATILE_RE.search(full))
        has_atomic_ok = '//@atomic_ok' in line
        out.append((name, is_atomic, is_volatile, i, full.strip(), has_atomic_ok))
    return out

def tokenize_mutex_list(arglist):
    return [x.strip() for x in arglist.split(',') if x.strip()]

def analyze_function(file_path, f_start_line, ftxt, guarded_map, issues, lock_pairs, lock_mismatch_records, critical_budget=50):
    body = ftxt[ftxt.find('{')+1: ftxt.rfind('}')]
    lines = body.splitlines()
    depth = 0
    held = {}  # mutex -> list of stacks (via, depth)
    raw_lock_counts = collections.Counter()

    acquisition_sequence = []

    def any_held(): return bool(held)

    def acquire(mtx, via):
        if mtx not in held:
            for already in held.keys():
                lock_pairs.add((already, mtx, file_path, f_start_line))
            acquisition_sequence.append(mtx)
            held[mtx] = []
        held[mtx].append((via, depth))

    def release_if_scope_ended():
        to_remove = []
        for mtx, stacks in list(held.items()):
            held[mtx] = [s for s in stacks if s[1] <= depth]
            if not held[mtx]:
                to_remove.append(mtx)
        for mtx in to_remove:
            held.pop(mtx, None)

    # compile guarded variable usage regexes once
    guarded_use_res = { var: (
            re.compile(ASSIGN_USE_RE_TMPL.format(name=re.escape(var))),
            re.compile(READ_USE_RE_TMPL.format(name=re.escape(var)))
        ) for var in guarded_map.keys()
    }

    # NEW: critical region span tracking
    crit_active = False
    crit_start_idx = None

    for idx, raw in enumerate(lines):
        ln = f_start_line + idx + 1
        line = raw.split("//",1)[0]

        # Track braces
        opens = line.count('{')
        closes = line.count('}')
        depth += opens

        # RAII acquisitions
        for rx in (RAII_LOCK_GUARD_RE, UNIQUE_LOCK_RE, FSCOPELOCK_RE):
            m = rx.search(line)
            if m:
                acquire(m.group(1), 'RAII')
        ms = SCOPED_LOCK_RE.search(line)
        if ms:
            for nm in tokenize_mutex_list(ms.group(1)):
                acquire(nm, 'RAII')

        # Raw lock/unlock
        for m in LOCK_CALL_RE.finditer(line):
            nm = m.group(1)
            raw_lock_counts[nm] += 1
            acquire(nm, 'RAW')
        for m in UNLOCK_CALL_RE.finditer(line):
            nm = m.group(1)
            raw_lock_counts[nm] -= 1
            if nm in held and held[nm]:
                held[nm].pop()
                if not held[nm]:
                    held.pop(nm, None)

        # Critical region tracking
        if any_held() and not crit_active:
            crit_active = True
            crit_start_idx = idx

        if not any_held() and crit_active:
            span = idx - (crit_start_idx or idx)
            if span >= critical_budget:
                issues.append(Issue("LONG-CRITICAL-BUDGET", file_path, f_start_line + (crit_start_idx or idx) + 1, 1,
                    f"Critical section spans ~{span} lines (>{critical_budget}). Consider shrinking or unlocking earlier.",
                    lines[crit_start_idx].strip() if crit_start_idx is not None and crit_start_idx < len(lines) else ""))
            crit_active = False
            crit_start_idx = None

        # LONG-CRITICAL-LOOP / LONG-CRITICAL-BLOCK while holding a lock
        if any_held():
            if INFINITE_LOOP_RE.search(line):
                issues.append(Issue("LONG-CRITICAL-LOOP", file_path, ln, 1,
                    "Infinite loop while a mutex is held (potential permanent lock hold).",
                    raw.strip()))
            if BLOCKING_CALL_RE.search(line):
                issues.append(Issue("LONG-CRITICAL-BLOCK", file_path, ln, 1,
                    "Blocking call while a mutex is held (risk of starvation/deadlock).",
                    raw.strip()))

        # LOCK-NOGUARD for guarded variables
        for var, (assign_re, read_re) in guarded_use_res.items():
            has_assign = assign_re.search(line) is not None
            has_read   = read_re.search(line) is not None
            if has_assign or has_read:
                needed, decl_line, decl_snippet = guarded_map[var]
                if needed not in held:
                    issues.append(Issue("LOCK-NOGUARD", file_path, ln, 1,
                        f"Access to '{var}' requires mutex '{needed}' (//@guarded_by({needed})) but it is not held here.",
                        raw.strip()))

        # CV-WAIT-NO-PRED: cv.wait* should be in while loop
        mcv = CV_WAIT_RE.search(line)
        if mcv:
            back = 3
            window = [l.strip() for l in lines[max(0, idx-back):idx+1]]
            if not any(w.startswith("while ") or w.startswith("while(") for w in window):
                issues.append(Issue("CV-WAIT-NO-PRED", file_path, ln, 1,
                    f"Condition variable '{mcv.group(1)}.{mcv.group(2)}' should be guarded by a while-predicate loop.",
                    raw.strip()))

        # Apply closing braces after checks
        depth -= closes
        if closes:
            release_if_scope_ended()

    # LOCK-MISMATCH: any raw lock left unmatched?
    for mtx, cnt in raw_lock_counts.items():
        if cnt > 0:
            lock_mismatch_records.append((file_path, f_start_line, mtx))

def analyze_file(path, issues, lock_pairs, lock_mismatch_records, atomic_issues, critical_budget):
    txt = read_text(path)
    if not txt: return
    guarded_map = build_guarded_map(txt)

    # ATOMIC-MISSING & VOLATILE-SYNC
    for name, is_atomic, is_volatile, ln, full_decl, has_atomic_ok in find_shared_decls(txt):
        if is_volatile:
            atomic_issues.append(Issue("VOLATILE-SYNC", path, ln, 1,
                f"'volatile' is not a synchronization primitive for shared variable '{name}'. Use std::atomic or a mutex.",
                full_decl))
        if not is_atomic and not has_atomic_ok:
            atomic_issues.append(Issue("ATOMIC-MISSING", path, ln, 1,
                f"Shared variable '{name}' is not atomic nor explicitly acknowledged (//@atomic_ok).",
                full_decl))

    # Function-wise
    for f_start_line, ftxt in split_functions(txt):
        analyze_function(path, f_start_line, ftxt, guarded_map, issues, lock_pairs, lock_mismatch_records, critical_budget)

def detect_lock_order_conflicts(lock_pairs):
    AB = {}
    conflicts = []
    for (a,b,f,l) in lock_pairs:
        AB.setdefault((a,b), []).append((f,l))
    for (a,b), locs in AB.items():
        if (b,a) in AB:
            conflicts.append(((a,b), locs, AB[(b,a)]))
    return conflicts

def print_report(root, issues, order_conflicts, mismatches, atomic_issues, mode):
    total = len(issues) + len(order_conflicts) + len(mismatches) + len(atomic_issues)
    root = os.path.abspath(root)
    def rel(p):
        try: return os.path.relpath(p, root)
        except: return p

    if mode == "FREE":
        # Provide categorical counts for dashboards
        cats = collections.Counter([it.tag for it in issues])
        print(f"[FREE] issues={total} | "
              f"guard={cats.get('LOCK-NOGUARD',0)} "
              f"order={len(order_conflicts)} "
              f"mismatch={len(mismatches)} "
              f"atomic={len([1 for x in atomic_issues if x.tag in ('ATOMIC-MISSING','VOLATILE-SYNC')])}")
        return 0

    print(f"[{mode}] Summary: total={total} | "
          f"LOCK-NOGUARD={sum(1 for it in issues if it.tag=='LOCK-NOGUARD')} | "
          f"LOCK-ORDER={len(order_conflicts)} | "
          f"LOCK-MISMATCH={len(mismatches)} | "
          f"LONG-CRIT={sum(1 for it in issues if it.tag.startswith('LONG-CRITICAL'))} | "
          f"ATOMIC/VOLATILE={len(atomic_issues)}")

    if order_conflicts:
        print("== Potential Deadlock (LOCK-ORDER) ==")
        for (a,b), loc1, loc2 in order_conflicts:
            for f,l in loc1:
                print(f"  {rel(f)}:{l}: acquires {a} -> {b}")
            for f,l in loc2:
                print(f"  {rel(f)}:{l}: acquires {b} -> {a}  (conflict)")
        print()

    if mismatches:
        print("== Lock/Unlock Mismatch (LOCK-MISMATCH) ==")
        for f,l,mtx in mismatches:
            print(f"  {rel(f)}:{l}: mutex '{mtx}' locked without matching unlock in this function")
        print()

    if atomic_issues:
        print("== Atomic / Volatile Issues ==")
        for it in atomic_issues:
            print(f"{rel(it.file)}:{it.line}:{it.col}: [{it.tag}] {it.msg}")
            if it.snippet:
                print(f"    {it.snippet}")
        print()

    if issues:
        print("== Guarded/Long Critical/Other Violations ==")
        for it in issues:
            print(f"{rel(it.file)}:{it.line}:{it.col}: [{it.tag}] {it.msg}")
            if it.snippet:
                print(f"    {it.snippet}")
        print()

    if mode == "WARNING":
        return 0
    if mode == "ABORT":
        return 1 if total > 0 else 0
    return 0

def main():
    ap = argparse.ArgumentParser(description="Heuristic concurrency checks for C/C++ projects (mutex/critical sections)")
    ap.add_argument("project_dir", help="Project root directory")
    ap.add_argument("--mode", choices=["FREE","WARNING","ABORT"], default="WARNING",
                    help="FREE: counts only; WARNING: details, never fail; ABORT: details, fail on issues")
    ap.add_argument("--exclude", action="append", default=[],
                    help="Substring filter to exclude paths (repeatable). Example: --exclude build --exclude third_party")
    ap.add_argument("--critical-budget", type=int, default=50,
                    help="Warn if a critical section stays held over this many source lines (default: 50)")
    args = ap.parse_args()

    root = os.path.abspath(args.project_dir)
    if not os.path.isdir(root):
        print(f"Not a directory: {root}", file=sys.stderr)
        sys.exit(2)

    issues = []               # LOCK-NOGUARD + LONG-CRITICAL-*
    lock_pairs = set()        # for LOCK-ORDER
    mismatches = []           # LOCK-MISMATCH
    atomic_issues = []        # ATOMIC-MISSING, VOLATILE-SYNC

    for p in iter_files(root, args.exclude):
        try:
            analyze_file(str(p), issues, lock_pairs, mismatches, atomic_issues, args.critical_budget)
        except Exception as e:
            print(f"[warn] failed to analyze {p}: {e}", file=sys.stderr)

    order_conflicts = detect_lock_order_conflicts(lock_pairs)
    code = print_report(root, issues, order_conflicts, mismatches, atomic_issues, args.mode)
    sys.exit(code)

if __name__ == "__main__":
    main()