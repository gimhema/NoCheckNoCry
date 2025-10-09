#!/usr/bin/env python3
# concurrency_preprocessor.py
# Heuristic, compiler-agnostic concurrency checks for C/C++ projects.
# Modes: FREE (counts only), WARNING (details, never fail), ABORT (details, fail on issues)
import sys, os, re, pathlib, collections, argparse

SRC_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"}

# ----------------------------
# Annotations (in comments)
# ----------------------------
#   //@guarded_by(M)    : member/global variable must be accessed under mutex/critical M
#   //@shared           : this variable is shared across threads (should be atomic or guarded)
#   //@atomic_ok        : acknowledge atomic-ness (suppresses ATOMIC-MISSING for this decl)
#   //@locks(M)         : function acquires mutex M (helps lock order detection if RAII patterns are not visible)
#
# Patterns we detect (heuristics):
#   LOCK-NOGUARD    : access to //@guarded_by(M) variable without M being held
#   LOCK-ORDER      : potential deadlock (A->B in one function, B->A in another)
#   LOCK-MISMATCH   : .lock() without matching .unlock() in function (use RAII)
#   CV-WAIT-NO-PRED : condition_variable wait not wrapped with while-predicate loop
#   ATOMIC-MISSING  : //@shared variable is non-atomic and not annotated //@atomic_ok
#   VOLATILE-SYNC   : volatile used for synchronization
#
# Notes:
# - This script is heuristic. It does not parse full C++ semantics or templates.
# - RAII-based lock scopes are approximated by brace depth.

Issue = collections.namedtuple("Issue", "tag file line col msg snippet")

# ------------ Regexes ------------
INCLUDE_RE         = re.compile(r'^\s*#\s*include\s*["<]([^">]+)[">]')
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

# Guarded variable use (read/write) – extremely heuristic:
ASSIGN_USE_RE_TMPL = r'(?<![\w:])(?:this->)?{name}\b\s*([+\-*/%&|^]?=|[\+\-]{2})'
READ_USE_RE_TMPL   = r'(?<![\w:])(?:this->)?{name}\b(?!\s*[:(])'   # not a label or function name

# Condition variable waits
CV_WAIT_RE         = re.compile(r'\b([A-Za-z_]\w*)\s*\.\s*(wait|wait_for|wait_until)\s*\(')

# Function splitting (heuristic)
FUNC_SIG_RE = re.compile(r'''(^|\s)(?:template\s*<[^>]*>\s*)?
    (?:[\w:\~\<\>\*&\s]+?)        # return + qualifiers
    \s+([\w:~]+)\s*               # name
    \(\s*([^\)]*)\s*\)\s*         # (params)
    (?:const\b|noexcept\b|override\b|final\b|\s)*\{''', re.X)

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
    """Return dict var_name -> mutex_name for //@guarded_by annotations in this file."""
    mapping = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = DECL_GUARDED_RE.search(line)
        if m:
            mapping[m.group('name')] = (m.group('mtx'), i, line.strip())
    return mapping

def find_shared_decls(text):
    """Return list of shared vars (name, is_atomic, is_volatile, line, full_decl, has_atomic_ok)."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = DECL_SHARED_RE.search(line)
        if not m: 
            # also allow //@shared at end of next comment line:
            continue
        name = m.group('name')
        full = m.group('full')
        is_atomic = bool(DECL_ATOMIC_RE.search(full))
        is_volatile = bool(VOLATILE_RE.search(full))
        has_atomic_ok = '//@atomic_ok' in line
        out.append((name, is_atomic, is_volatile, i, full.strip(), has_atomic_ok))
    return out

def tokenize_mutex_list(arglist):
    # from "m1, m2, lockA" -> ["m1","m2","lockA"]
    return [x.strip() for x in arglist.split(',') if x.strip()]

def analyze_function(file_path, f_start_line, ftxt, guarded_map, issues, lock_pairs, lock_mismatch_records):
    body = ftxt[ftxt.find('{')+1: ftxt.rfind('}')]
    lines = body.splitlines()
    depth = 0
    held = {}  # mutex -> list of depths where acquired (for RAII scope tracking)
    raw_lock_counts = collections.Counter()  # mutex -> count of .lock() - .unlock()

    # Ordered acquisition sequence for lock order check.
    acquisition_sequence = []  # list of mutex names in order of first acquisition in this function

    def acquire(mtx, via):
        # record lock order pair edges
        if mtx not in held:
            # when acquiring mtx, pair all currently held -> mtx
            for already in held.keys():
                lock_pairs.add((already, mtx, file_path, f_start_line))
            acquisition_sequence.append(mtx)
            held[mtx] = []
        held[mtx].append((via, depth))

    def release_if_scope_ended():
        # drop RAII-held locks whose depth is now less than acquire depth
        to_remove = []
        for mtx, stacks in held.items():
            held[mtx] = [s for s in stacks if s[1] <= depth]
            if not held[mtx]:
                to_remove.append(mtx)
        for mtx in to_remove:
            held.pop(mtx, None)

    # compile guarded variable usage regexes once
    guarded_use_res = {}
    for var in guarded_map.keys():
        guarded_use_res[var] = (
            re.compile(ASSIGN_USE_RE_TMPL.format(name=re.escape(var))),
            re.compile(READ_USE_RE_TMPL.format(name=re.escape(var)))
        )

    for idx, raw in enumerate(lines):
        ln = f_start_line + idx + 1
        line = raw.split("//",1)[0]

        # track depth
        opens = line.count('{')
        closes = line.count('}')
        depth += opens

        # RAII acquisitions
        for rx in (RAII_LOCK_GUARD_RE, UNIQUE_LOCK_RE, FSCOPELOCK_RE):
            m = rx.search(line)
            if m:
                acquire(m.group(1), 'RAII')

        # scoped_lock may acquire multiple
        ms = SCOPED_LOCK_RE.search(line)
        if ms:
            for nm in tokenize_mutex_list(ms.group(1)):
                acquire(nm, 'RAII')

        # Raw lock/unlock tracking
        for m in LOCK_CALL_RE.finditer(line):
            nm = m.group(1)
            raw_lock_counts[nm] += 1
            acquire(nm, 'RAW')
        for m in UNLOCK_CALL_RE.finditer(line):
            nm = m.group(1)
            raw_lock_counts[nm] -= 1
            # best-effort: release one layer
            if nm in held and held[nm]:
                held[nm].pop()
                if not held[nm]:
                    held.pop(nm, None)

        # LOCK-NOGUARD: guarded var accessed without holding its mutex
        for var, (assign_re, read_re) in guarded_use_res.items():
            if assign_re.search(line) or read_re.search(line):
                needed, decl_line, decl_snippet = guarded_map[var]
                if needed not in held:
                    issues.append(Issue("LOCK-NOGUARD", file_path, ln, 1,
                        f"Access to '{var}' requires mutex '{needed}' (//@guarded_by({needed})) but it is not held here.",
                        raw.strip()))

        # CV-WAIT-NO-PRED: cv.wait* should be in while loop
        mcv = CV_WAIT_RE.search(line)
        if mcv:
            # look back a few lines for 'while (...)'
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

def analyze_file(path, issues, lock_pairs, lock_mismatch_records, atomic_issues):
    txt = read_text(path)
    if not txt: return
    # File-level annotations
    guarded_map = build_guarded_map(txt)

    # ATOMIC-MISSING & VOLATILE-SYNC (at declaration)
    for name, is_atomic, is_volatile, ln, full_decl, has_atomic_ok in find_shared_decls(txt):
        if is_volatile:
            atomic_issues.append(Issue("VOLATILE-SYNC", path, ln, 1,
                f"'volatile' is not a synchronization primitive for shared variable '{name}'. Use std::atomic or a mutex.",
                full_decl))
        if not is_atomic and not has_atomic_ok:
            atomic_issues.append(Issue("ATOMIC-MISSING", path, ln, 1,
                f"Shared variable '{name}' is not atomic nor explicitly acknowledged (//@atomic_ok).",
                full_decl))

    # Function-wise scan
    for f_start_line, ftxt in split_functions(txt):
        analyze_function(path, f_start_line, ftxt, guarded_map, issues, lock_pairs, lock_mismatch_records)

def detect_lock_order_conflicts(lock_pairs):
    """
    lock_pairs: set of (A,B,file,line) meaning A held before acquiring B
    conflict if there exists (A,B) and (B,A) in different functions/locations
    """
    AB = {}
    BA_conflicts = []
    for (a,b,f,l) in lock_pairs:
        AB.setdefault((a,b), []).append((f,l))
    for (a,b), locs in AB.items():
        if (b,a) in AB:
            BA_conflicts.append(((a,b), locs, AB[(b,a)]))
    return BA_conflicts

def print_report(root, issues, order_conflicts, mismatches, atomic_issues, mode):
    total = len(issues) + len(order_conflicts) + len(mismatches) + len(atomic_issues)
    root = os.path.abspath(root)
    def rel(p): 
        try: return os.path.relpath(p, root)
        except: return p

    if mode == "FREE":
        print(f"[FREE] issues={total} (guard={len(issues)}, order={len(order_conflicts)}, mismatch={len(mismatches)}, atomic={len(atomic_issues)})")
        return 0

    print(f"[{mode}] Summary: total={total} | LOCK-NOGUARD={len(issues)} | LOCK-ORDER={len(order_conflicts)} | LOCK-MISMATCH={len(mismatches)} | ATOMIC/VOLATILE={len(atomic_issues)}")

    if order_conflicts:
        print("== Potential Deadlock (LOCK-ORDER) ==")
        for (a,b), loc1, loc2 in order_conflicts:
            for f,l in loc1:
                print(f"  {rel(f)}:{l}: acquires {a} -> {b}")
            for f,l in loc2:
                print(f"  {rel(f)}:{l}: acquires {b} -> {a}  (conflict)")

    if mismatches:
        print("\n== Lock/Unlock Mismatch (LOCK-MISMATCH) ==")
        for f,l,mtx in mismatches:
            print(f"  {rel(f)}:{l}: mutex '{mtx}' locked without matching unlock in this function")

    if atomic_issues:
        print("\n== Atomic / Volatile Issues ==")
        for it in atomic_issues:
            print(f"{rel(it.file)}:{it.line}:{it.col}: [{it.tag}] {it.msg}")
            print(f"    {it.snippet}")

    if issues:
        print("\n== Guarded Access Violations (LOCK-NOGUARD) ==")
        for it in issues:
            print(f"{rel(it.file)}:{it.line}:{it.col}: [{it.tag}] {it.msg}")
            print(f"    {it.snippet}")

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
    args = ap.parse_args()

    root = os.path.abspath(args.project_dir)
    if not os.path.isdir(root):
        print(f"Not a directory: {root}", file=sys.stderr)
        sys.exit(2)

    issues = []               # LOCK-NOGUARD
    lock_pairs = set()        # for LOCK-ORDER
    mismatches = []           # LOCK-MISMATCH
    atomic_issues = []        # ATOMIC-MISSING, VOLATILE-SYNC

    for p in iter_files(root, args.exclude):
        try:
            analyze_file(str(p), issues, lock_pairs, mismatches, atomic_issues)
        except Exception as e:
            print(f"[warn] failed to analyze {p}: {e}", file=sys.stderr)

    order_conflicts = detect_lock_order_conflicts(lock_pairs)
    code = print_report(root, issues, order_conflicts, mismatches, atomic_issues, args.mode)
    sys.exit(code)

if __name__ == "__main__":
    main()
