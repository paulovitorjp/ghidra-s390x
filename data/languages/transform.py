#!/usr/bin/env python3
"""Transform s390x .sinc files to valid SLEIGH syntax.
- Rename token fields to TOKEN_FIELD (globally unique)
- Transform constructor headers: :MNEMONIC TOKEN oplist is PATTERN [DISPLAY]
  -> :MNEMONIC DISPLAY_PIECES is PATTERN
- Rename field references in pcode (context-aware per constructor token)
"""
import re
import sys

def parse_tokens(text):
    """Return {token: [fields]} from define token blocks."""
    tokens = {}
    for m in re.finditer(r'define\s+token\s+(\w+)\s*\(\s*\d+\s*\)(.*?);', text, re.DOTALL):
        tok, body = m.group(1), m.group(2)
        # Fields may already be prefixed (if this file was processed)
        # Extract base names: look for TOK_field or field
        fields = []
        for fm in re.finditer(r'^\s*(?:' + tok + r'_)?(\w+)\s*=\s*\(', body, re.MULTILINE):
            fields.append(fm.group(1))
        tokens[tok] = fields
    return tokens

def rename_token_fields(text, tokens):
    """Rename fields in define token blocks to TOKEN_FIELD."""
    def rename_block(m):
        tok, bits, body = m.group(1), m.group(2), m.group(3)
        def rf(fm):
            ws, fname = fm.group(1), fm.group(2)
            # Don't double-prefix
            if fname.startswith(tok + '_'):
                return f"{ws}{fname} = ("
            return f"{ws}{tok}_{fname} = ("
        body = re.sub(r'^(\s*)(\w+)\s*=\s*\(', rf, body, flags=re.MULTILINE)
        return f"define token {tok}({bits}){body};"
    return re.sub(r'define\s+token\s+(\w+)\s*\(\s*(\d+)\s*\)(.*?);',
                  rename_block, text, flags=re.DOTALL)

def split_constructor_header(header_text):
    """Parse old header: :MNEMONIC TOKEN oplist is PATTERN [DISPLAY]
    Returns (mnemonic, token, oplist_str, pattern_str, display_str or None).
    header_text is everything from ':' up to (but not including) the '{'.
    """
    # Remove leading ':' and strip
    t = header_text.strip()
    assert t.startswith(':'), t[:50]
    t = t[1:].strip()
    # Mnemonic is first word
    m = re.match(r'(\S+)\s+(.*)', t, re.DOTALL)
    mnemonic, rest = m.group(1), m.group(2).strip()
    # Token is next word
    m = re.match(r'(\S+)\s+(.*)', rest, re.DOTALL)
    token, rest = m.group(1), m.group(2).strip()
    # Split off display [...] if present (at the end, before '{')
    display = None
    # Find 'is' keyword - pattern starts after 'is'
    # The oplist is between token and 'is'
    # Use regex to find ' is ' (word boundary)
    im = re.search(r'\bis\b', rest)
    assert im, f"no 'is' in: {rest[:80]}"
    oplist_str = rest[:im.start()].strip()
    after_is = rest[im.end():].strip()
    # Check for [DISPLAY] at end
    # Display is [...] - find matching brackets from the end
    if after_is.rstrip().endswith(']'):
        # Find the opening '[' that matches the final ']'
        # Simple approach: find last '[' that isn't inside a string
        # For our files, display is the last [...] block
        idx = after_is.rfind('[')
        # Make sure there's no '{' after it (there isn't, we cut at '{')
        display = after_is[idx+1:-1].strip()
        pattern_str = after_is[:idx].strip()
    else:
        pattern_str = after_is.strip()
    return mnemonic, token, oplist_str, pattern_str, display

def transform_display(display, mnemonic, token, field_map, constrained=None):
    """Transform old display pieces into header print pieces.
    field_map: {old_field: new_field}
    constrained: {new_field: constant_value} for fields fixed in pattern
    Returns a string like: "MNEMONIC " TOK_F1 "," TOK_F2
    """
    if constrained is None:
        constrained = {}
    if display is None:
        return None
    # Tokenize the display: strings, $(...), bare words, punctuation
    # For commas, track if followed by whitespace (separator vs meaningful)
    pieces = []  # (type, value, followed_by_space)
    i = 0
    n = len(display)
    while i < n:
        c = display[i]
        if c.isspace():
            i += 1
            continue
        followed_by_space = (i+1 < n and display[i+1].isspace())
        # Actually, check if NEXT non-space char... simpler: check immediate next
        if c == '"':
            # Quoted string
            j = display.index('"', i+1)
            pieces.append(('str', display[i:j+1], False))
            i = j + 1
        elif c == '$' and i+1 < n and display[i+1] == '(':
            # $(...)
            depth = 1
            j = i + 2
            while depth > 0:
                if display[j] == '(': depth += 1
                elif display[j] == ')': depth -= 1
                j += 1
            inner = display[i+2:j-1].strip()
            pieces.append(('macro', inner, False))
            i = j
        elif c in '(),':
            # For comma, check if it's a separator (followed by space + another piece)
            # vs meaningful (part of display like in $(R1),$(R2))
            is_sep = False
            if c == ',':
                # Look ahead: skip whitespace, see what's next
                k = i + 1
                while k < n and display[k].isspace():
                    k += 1
                # If we skipped whitespace and there's more, it's likely a separator
                # If no whitespace was skipped, it's meaningful
                is_sep = (k > i + 1)
            pieces.append(('punct', c, is_sep))
            i += 1
        else:
            # Bare word
            m = re.match(r'[A-Za-z_][A-Za-z0-9_]*', display[i:])
            if m:
                pieces.append(('word', m.group(0), False))
                i += len(m.group(0))
            else:
                pieces.append(('str', f'"{c}"', False))
                i += 1
    
    # Convert pieces to header format
    out = []
    for typ, val, is_sep in pieces:
        if typ == 'str':
            out.append(val)
        elif typ == 'macro':
            # $(FIELD) -> FIELD (prefix it).
            inner_fields = re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', val)
            if len(inner_fields) == 1 and inner_fields[0] in field_map:
                pf = field_map[inner_fields[0]]
                if pf in constrained:
                    out.append(f'"{constrained[pf]}"')
                else:
                    out.append(pf)
            elif len(inner_fields) == 1:
                out.append(inner_fields[0])
            else:
                pass
        elif typ == 'punct':
            if val == ',':
                if not is_sep:
                    out.append('","')
                # else: separator, skip
            else:
                out.append(f'"{val}"')
        elif typ == 'word':
            if val in field_map:
                pf = field_map[val]
                if pf in constrained:
                    # Field is constrained to a constant; print the constant
                    out.append(f'"{constrained[pf]}"')
                else:
                    out.append(pf)
            elif val == mnemonic or val.lower() == mnemonic.lower():
                out.append(f'"{val} "')
            else:
                out.append(f'"{val}"')
    return ' '.join(out)

def get_printable_operands(oplist_str, field_map):
    """From oplist like 'OP=0x18, R1, R2', return [prefixed_R1, prefixed_R2]
    (those without =value)."""
    ops = []
    for part in oplist_str.split(','):
        part = part.strip()
        if not part:
            continue
        # Split on '=' - if there's a value, it's constrained (not printed)
        if '=' in part:
            continue
        # It's a bare field -> printable operand
        if part in field_map:
            ops.append(field_map[part])
        else:
            # Might be something else - keep as-is?
            ops.append(part)
    return ops

def rename_fields_in_text(text, field_map):
    """Rename all field occurrences (word boundary) using field_map."""
    # Sort by length descending to avoid partial matches (e.g., OP2 before OP)
    for old in sorted(field_map, key=len, reverse=True):
        new = field_map[old]
        text = re.sub(r'\b' + re.escape(old) + r'\b', new, text)
    return text

def transform_constructors(text, tokens):
    """Transform all constructors in the text."""
    # Build field maps per token: {token: {old: new}}
    token_field_map = {}
    for tok, fields in tokens.items():
        token_field_map[tok] = {f: f"{tok}_{f}" for f in fields}
    
    # Find constructors: from ^: to the matching { ... }
    out_parts = []
    last_end = 0
    
    pos = 0
    n = len(text)
    while pos < n:
        m = re.search(r'^:', text[pos:], re.MULTILINE)
        if not m:
            break
        cstart = pos + m.start()
        hpos = cstart
        in_bracket = 0
        in_string = False
        header_end = None
        while hpos < n:
            c = text[hpos]
            if in_string:
                if c == '"':
                    in_string = False
            elif c == '"':
                in_string = True
            elif c == '[':
                in_bracket += 1
            elif c == ']':
                in_bracket -= 1
            elif c == '{' and in_bracket == 0:
                header_end = hpos
                break
            hpos += 1
        
        if header_end is None:
            break
        
        header_text = text[cstart:header_end]
        depth = 1
        ppos = header_end + 1
        in_string = False
        while ppos < n and depth > 0:
            c = text[ppos]
            if in_string:
                if c == '"':
                    in_string = False
            elif c == '"':
                in_string = True
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
            ppos += 1
        pcode_end = ppos
        pcode_text = text[header_end:pcode_end]
        
        try:
            mnemonic, token, oplist_str, pattern_str, display = split_constructor_header(header_text)
        except Exception as e:
            print(f"WARNING: failed to parse header at {cstart}: {e}", file=sys.stderr)
            out_parts.append(text[last_end:pcode_end])
            last_end = pcode_end
            pos = pcode_end
            continue
        
        if token not in token_field_map:
            print(f"WARNING: unknown token {token} at {cstart}", file=sys.stderr)
            out_parts.append(text[last_end:pcode_end])
            last_end = pcode_end
            pos = pcode_end
            continue
        
        field_map = token_field_map[token]
        
        # Transform pattern: rename fields
        new_pattern = rename_fields_in_text(pattern_str, field_map)
        
        # Find fields constrained to constants in the pattern
        # e.g., RSa_R1=0 -> {RSa_R1: 0}
        constrained = {}
        for cm in re.finditer(r'\b(' + '|'.join(re.escape(f) for f in field_map.values()) + r')\s*=\s*(0x[0-9a-fA-F]+|\d+)', new_pattern):
            constrained[cm.group(1)] = cm.group(2)
        
        # Transform display or synthesize
        if display is not None:
            disp_pieces = transform_display(display, mnemonic, token, field_map, constrained)
        else:
            disp_pieces = None
        
        if disp_pieces is None:
            pop = get_printable_operands(oplist_str, field_map)
            # Filter out constrained fields
            pop = [p for p in pop if p not in constrained]
            if pop:
                parts = [f'"{mnemonic} "']
                for j, p in enumerate(pop):
                    if j > 0:
                        parts.append('","')
                    parts.append(p)
                disp_pieces = ' '.join(parts)
            else:
                disp_pieces = f'"{mnemonic}"'
        
        new_header = f":{mnemonic} {disp_pieces} is {new_pattern}\n"
        new_pcode = rename_fields_in_text(pcode_text, field_map)
        
        out_parts.append(text[last_end:cstart])
        out_parts.append(new_header)
        out_parts.append(new_pcode)
        last_end = pcode_end
        pos = pcode_end
    
    out_parts.append(text[pos:])
    return ''.join(out_parts)

def main():
    fname = sys.argv[1]
    text = open(fname).read()
    tokens = parse_tokens(text)
    # Also load tokens from s390x.slaspec and all .sinc files (for .sinc files)
    if fname.endswith('.sinc'):
        import glob
        merged = {}
        for tf in ['s390x.slaspec'] + sorted(glob.glob('s390x_*.sinc')):
            try:
                ttext = open(tf).read()
                # Parse tokens from the ORIGINAL (untransformed) text if available
                # For now, parse current text (fields may be prefixed)
                for tok, fields in parse_tokens(ttext).items():
                    if tok not in merged:
                        merged[tok] = fields
            except FileNotFoundError:
                pass
        # Current file's tokens take precedence
        merged.update(tokens)
        tokens = merged
    print(f"{fname}: tokens {list(tokens.keys())}", file=sys.stderr)
    text = rename_token_fields(text, tokens)
    # Re-parse (fields now prefixed) - but keep the merged token map
    # for constructor transformation
    text = transform_constructors(text, tokens)
    open(fname, 'w').write(text)
    print(f"{fname}: done", file=sys.stderr)

if __name__ == '__main__':
    main()
