#!/usr/bin/env python3
"""Post-process transformed .sinc files: fix wide literals, while loops,
sext/zext on fields, :N truncation, C-style ifs."""
import re
import glob
import sys

def fix_wide_literals(text):
    replacements = {
        '0x000000007FFFFFFF': '0x7FFFFFFF',
        '0x00000000ffffffff': '0xffffffff',
        '0x0007FFFF80000000': '((0x7FFFF << 32) | 0x80000000)',
        '0x0008000000000000': '(0x80000 << 32)',
        '0x00FFFFFFFFFFFFFF': '((0xFFFFFF << 32) | 0xFFFFFFFF)',
        '0x7fffffffffffffff': '((0x7FFFFFFF << 32) | 0xFFFFFFFF)',
        '0xFFF0000000000000': '(0xFFF00000 << 32)',
        '0xffffffff00000000': '(0xFFFFFFFF << 32)',
        '0xFFFFFFFF00000000': '(0xFFFFFFFF << 32)',
        '0x7FFFFFFFFFFFFFFF': '((0x7FFFFFFF << 32) | 0xFFFFFFFF)',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text

def fix_while_loops(text):
    out = []
    pos = 0
    n = len(text)
    loop_id = 0
    while pos < n:
        m = re.search(r'\bwhile\s*\(', text[pos:])
        if not m:
            out.append(text[pos:])
            break
        wstart = pos + m.start()
        pstart = pos + m.end() - 1
        depth = 1
        p = pstart + 1
        while depth > 0:
            if text[p] == '(': depth += 1
            elif text[p] == ')': depth -= 1
            p += 1
        cond = text[pstart+1:p-1].strip()
        q = p
        while q < n and text[q].isspace():
            q += 1
        if text[q] != '{':
            out.append(text[pos:q])
            pos = q
            continue
        depth = 1
        r = q + 1
        in_str = False
        while depth > 0:
            c = text[r]
            if in_str:
                if c == '"': in_str = False
            elif c == '"': in_str = True
            elif c == '{': depth += 1
            elif c == '}': depth -= 1
            r += 1
        body = text[q+1:r-1]
        line_start = text.rfind('\n', 0, wstart) + 1
        indent = text[line_start:wstart]
        # Invert
        mc = re.match(r'(.*?)\s*!=\s*(.*)', cond)
        if mc:
            inv = f"{mc.group(1).strip()} == {mc.group(2).strip()}"
        else:
            mc = re.match(r'(.*?)\s*==\s*(.*)', cond)
            if mc:
                inv = f"{mc.group(1).strip()} != {mc.group(2).strip()}"
            else:
                inv = f"!({cond})"
        loop_id += 1
        lbl_start = f"<loop_{loop_id}_start>"
        lbl_end = f"<loop_{loop_id}_end>"
        body_lines = []
        for line in body.split('\n'):
            if line.startswith('    '):
                body_lines.append(line[4:])
            else:
                body_lines.append(line)
        body = '\n'.join(body_lines)
        new_code = (f"{indent}{lbl_start}\n"
                    f"{indent}if ({inv}) goto {lbl_end};\n"
                    f"{body}\n"
                    f"{indent}goto {lbl_start};\n"
                    f"{indent}{lbl_end}")
        out.append(text[pos:wstart])
        out.append(new_code)
        pos = r
    return ''.join(out)

def build_field_size_map(fnames):
    """Build {field_name: size_in_bytes} from token definitions in files."""
    field_sizes = {}
    for fname in fnames:
        try:
            text = open(fname).read()
        except:
            continue
        # Find: FIELD = (start, end)
        for m in re.finditer(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)', text, re.MULTILINE):
            field = m.group(1)
            start, end = int(m.group(2)), int(m.group(3))
            bits = end - start + 1
            # Only if it looks like a token field (has underscore and prefix)
            if '_' in field:
                field_sizes[field] = (bits + 7) // 8
    return field_sizes

_FIELD_SIZES = {}

def get_field_size(field, text):
    # Use global map if available
    if field in _FIELD_SIZES:
        return _FIELD_SIZES[field]
    m = re.search(rf'{re.escape(field)}\s*=\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)', text)
    if m:
        start, end = int(m.group(1)), int(m.group(2))
        bits = end - start + 1
        return (bits + 7) // 8
    return None

def fix_sext_zext(text):
    def rewrite_stmt(m):
        indent = m.group(1)
        lhs = m.group(2).strip()
        func = m.group(3)
        field = m.group(4)
        if '_' not in field:
            return m.group(0)
        size = get_field_size(field, text)
        if size is None:
            return m.group(0)
        tmp = f"_ext_{field.lower()}"
        return f"{indent}local {tmp}:{size};\n{indent}{tmp} = {field};\n{indent}{lhs} = {func}({tmp});"
    return re.sub(r'^([ \t]*)([^=\n;]+?)\s*=\s*(sext|zext)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;',
                  rewrite_stmt, text, flags=re.MULTILINE)

def fix_truncation(text):
    def fix_inner(expr, size_str):
        size = int(size_str)
        expr = expr.strip()
        if size == 1:
            mask = "0xff"
        elif size == 2:
            mask = "0xffff"
        elif size == 4:
            mask = "0xffffffff"
        else:
            return f"{expr}:{size}"
        return f"({expr} & {mask})"
    # Avoid matching 'local x:4;'
    # Use negative lookbehind for 'local'
    return re.sub(r'(?<![A-Za-z_])=\s*([^=;\n]+?):(\d+)\s*;',
                  lambda m: f"= {fix_inner(m.group(1), m.group(2))};", text)

def invert_cond(cond):
    cond = cond.strip()
    m = re.match(r'(.*?)\s*!=\s*(.*)', cond)
    if m:
        return f"{m.group(1).strip()} == {m.group(2).strip()}"
    m = re.match(r'(.*?)\s*==\s*(.*)', cond)
    if m:
        return f"{m.group(1).strip()} != {m.group(2).strip()}"
    return f"!({cond})"

_label_counter = 0
def convert_ifs(text):
    global _label_counter
    out = []
    pos = 0
    n = len(text)
    while pos < n:
        m = re.search(r'\bif\s*\(', text[pos:])
        if not m:
            out.append(text[pos:])
            break
        if_start = pos + m.start()
        pstart = pos + m.end() - 1
        depth = 1
        p = pstart + 1
        while depth > 0 and p < n:
            if text[p] == '(': depth += 1
            elif text[p] == ')': depth -= 1
            p += 1
        cond = text[pstart+1:p-1].strip()
        q = p
        while q < n and text[q].isspace():
            q += 1
        if text[q:q+4] == 'goto':
            out.append(text[pos:q+4])
            pos = q + 4
            continue
        if text[q] != '{':
            out.append(text[pos:q])
            pos = q
            continue
        depth = 1
        r = q + 1
        in_str = False
        while depth > 0 and r < n:
            c = text[r]
            if in_str:
                if c == '"': in_str = False
            elif c == '"': in_str = True
            elif c == '{': depth += 1
            elif c == '}': depth -= 1
            r += 1
        body = text[q+1:r-1]
        s = r
        while s < n and text[s].isspace():
            s += 1
        has_else = text[s:s+4] == 'else'
        else_body = None
        else_end = r
        if has_else:
            t = s + 4
            while t < n and text[t].isspace():
                t += 1
            if text[t] == '{':
                depth = 1
                u = t + 1
                while depth > 0 and u < n:
                    if text[u] == '{': depth += 1
                    elif text[u] == '}': depth -= 1
                    u += 1
                else_body = text[t+1:u-1]
                else_end = u
        line_start = text.rfind('\n', 0, if_start) + 1
        indent = text[line_start:if_start]
        _label_counter += 1
        lbl_end = f"<if_{_label_counter}_end>"
        lbl_else = f"<if_{_label_counter}_else>" if has_else else None
        body = convert_ifs(body)
        if else_body:
            else_body = convert_ifs(else_body)
        inv = invert_cond(cond)
        if has_else:
            new_code = (f"{indent}if ({inv}) goto {lbl_else};\n"
                        f"{body}\n"
                        f"{indent}goto {lbl_end};\n"
                        f"{indent}{lbl_else}\n"
                        f"{else_body}\n"
                        f"{indent}{lbl_end}")
        else:
            new_code = (f"{indent}if ({inv}) goto {lbl_end};\n"
                        f"{body}\n"
                        f"{indent}{lbl_end}")
        out.append(text[pos:if_start])
        out.append(new_code)
        pos = else_end if has_else else r
    return ''.join(out)

def main():
    fnames = sys.argv[1:] if len(sys.argv) > 1 else glob.glob('s390x_*.sinc')
    # Build global field size map from all files (including main slaspec)
    global _FIELD_SIZES
    all_files = fnames + ['s390x.slaspec']
    _FIELD_SIZES = build_field_size_map(all_files)
    print(f"Built field size map: {len(_FIELD_SIZES)} fields", file=sys.stderr)
    for fname in fnames:
        text = open(fname).read()
        text = fix_wide_literals(text)
        text = fix_while_loops(text)
        text = fix_sext_zext(text)
        text = fix_truncation(text)
        global _label_counter
        _label_counter = 0
        text = convert_ifs(text)
        open(fname, 'w').write(text)
        print(f"{fname}: post-processed", file=sys.stderr)

if __name__ == '__main__':
    main()
