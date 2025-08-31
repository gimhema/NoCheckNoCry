import re
import sys

# 정규식 패턴 정의
pointer_decl_pattern = re.compile(r'\b([\w:]+)\s*\*\s*(\w+)\s*;')  # T* var;
null_check_pattern = re.compile(r'if\s*\(\s*(\w+)\s*(?:!=\s*nullptr)?\s*\)')  # if(var) or if(var != nullptr)
arrow_usage_pattern = re.compile(r'(\w+)->')

def analyze_cpp_file(filepath: str):
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    pointer_vars = {}   # {var: line_number}
    checked_vars = set()

    for i, line in enumerate(lines, start=1):
        # 포인터 선언 찾기
        decl_match = pointer_decl_pattern.search(line)
        if decl_match:
            varname = decl_match.group(2)
            pointer_vars[varname] = i

        # null 체크 찾기
        check_match = null_check_pattern.search(line)
        if check_match:
            varname = check_match.group(1)
            checked_vars.add(varname)

        # -> 사용 찾기
        arrow_match = arrow_usage_pattern.search(line)
        if arrow_match:
            varname = arrow_match.group(1)
            if varname in pointer_vars and varname not in checked_vars:
                print(f"[경고] '{varname}' 포인터가 라인 {pointer_vars[varname]}에서 선언되었으나, "
                      f"NULL 체크 없이 라인 {i}에서 사용됨.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"사용법: python {sys.argv[0]} <cpp파일>")
        sys.exit(1)

    analyze_cpp_file(sys.argv[1])
