#!/usr/bin/env python3
"""
check-livecodescript.py - the static gate for the LCB / livecodescript layer.

OXT is a GUI runtime: there is no headless way to compile or run .lcb or
.livecodescript here, so the static checks below are the only automated safety
net the script layer gets. Each check encodes a gotcha that OXT compilation (or
silent misbehaviour) would otherwise punish, paid for while building TorrentXT
and carried over (see CLAUDE.md, "LiveCodeScript / LCB / OXT gotchas"):

  1. Smart/curly quotes and em/en dashes  - they fail OXT compilation and break
     house style. ASCII " and ' only; hyphens, not dashes.
  2. handler / if / repeat / unsafe balance - an unbalanced block is a compile
     error; a stray or missing `end unsafe` mis-scopes every foreign call.
  3. constant-declared-before-use         - OXT resolves a constant by lexical
     position; a forward reference silently evaluates to nothing.
  4. the prefixed-token-shadow trap        - a t/p/s/k-prefixed name whose full
     spelling lowercases to a reserved token (the classic `tExt` == `text`)
     compiles and silently misbehaves.

Run with no arguments to check every .lcb / .livecodescript under the repo, or
pass explicit paths. Exits non-zero if any check fails.

This is a re-implementation, to the CLAUDE.md specification, of TorrentXT's
checker; reconcile it against that original if one becomes available.
"""

import os
import re
import sys

# Curly quotes (U+2018/2019/201C/201D) and en/em dashes (U+2013/2014). The first
# four fail OXT compilation; the dashes violate house style.
BANNED_CHARS = {
    "‘": "left single curly quote",
    "’": "right single curly quote",
    "“": "left double curly quote",
    "”": "right double curly quote",
    "–": "en dash (use a hyphen)",
    "—": "em dash (use a hyphen)",
}

# Reserved xTalk / LCB tokens. Used only by the shadow-trap check, and only for
# identifiers that are clearly the author's (mixed case) rather than a bare
# keyword, so an over-broad entry here is harmless unless a t/p/s/k identifier
# happens to collide with it (which is exactly what we want to catch).
RESERVED = {
    "a", "an", "after", "add", "and", "are", "as", "before", "begin", "boolean",
    "break", "by", "byte", "char", "character", "codepoint", "codeunit",
    "command", "constant", "continue", "data", "default", "divide", "do", "each",
    "element", "else", "empty", "end", "event", "exit", "false", "for", "foreign",
    "from", "function", "get", "getter", "global", "handler", "if", "in",
    "integer", "into", "is", "it", "item", "key", "kind", "library", "line",
    "list", "local", "me", "metadata", "module", "multiply", "next", "not",
    "nothing", "number", "of", "on", "or", "otherwise", "paragraph", "pass",
    "pointer", "private", "property", "public", "put", "real", "repeat", "result",
    "return", "sentence", "set", "setter", "sort", "string", "subtract", "target",
    "text", "the", "then", "this", "throw", "to", "token", "true", "trueword",
    "type", "unsafe", "until", "use", "value", "variable", "where", "while",
    "with", "without", "word",
}

LCB_HANDLER_OPENERS = ("handler",)               # .lcb: handler / public handler
SCRIPT_HANDLER_OPENERS = ("on", "command", "function", "getter", "setter")


class Problem:
    def __init__(self, path, line, message):
        self.path = path
        self.line = line
        self.message = message

    def __str__(self):
        return f"{self.path}:{self.line}: {self.message}"


def strip_block_comments(text):
    """Blank out /* ... */ spans, preserving newlines so line numbers hold."""
    out = []
    i, n = 0, len(text)
    in_block = False
    while i < n:
        if not in_block and text[i] == "/" and i + 1 < n and text[i + 1] == "*":
            in_block = True
            out.append("  ")
            i += 2
            continue
        if in_block and text[i] == "*" and i + 1 < n and text[i + 1] == "/":
            in_block = False
            out.append("  ")
            i += 2
            continue
        if in_block:
            out.append("\n" if text[i] == "\n" else " ")
        else:
            out.append(text[i])
        i += 1
    return "".join(out)


def strip_line(line):
    """Remove string literals and -- // line comments from one (block-comment-
    free) line, replacing removed runs with spaces so columns are preserved.
    Keyword and identifier checks run on the result, so nothing inside a string
    or comment is mistaken for code."""
    out = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c == '"':                      # xTalk strings have no backslash escape
            out.append(" ")
            i += 1
            while i < n and line[i] != '"':
                out.append(" ")
                i += 1
            if i < n:                     # the closing quote
                out.append(" ")
                i += 1
            continue
        if c == "-" and i + 1 < n and line[i + 1] == "-":
            break                         # -- line comment to end of line
        if c == "/" and i + 1 < n and line[i + 1] == "/":
            break                         # // line comment to end of line
        out.append(c)
        i += 1
    return "".join(out)


def check_banned_chars(path, raw_lines, problems):
    for lineno, raw in enumerate(raw_lines, start=1):
        for col, ch in enumerate(raw, start=1):
            if ch in BANNED_CHARS:
                problems.append(Problem(
                    path, lineno,
                    f"banned character at column {col}: {BANNED_CHARS[ch]}"))


def classify_opener(tokens, is_script):
    """Return the block kind this line opens, or None. tokens are lowercase."""
    if not tokens:
        return None
    first = tokens[0]
    if first == "foreign":
        return None                       # single-line foreign declaration
    # The module-level declaration is itself a block: an LCB library/module/
    # widget must be closed with `end library` / `end module` / `end widget`.
    # Missing that terminator is a parse-to-EOF "syntax error" in OXT, so it is
    # tracked here like any other block.
    if first in ("library", "module", "widget"):
        return first
    if first == "handler":
        return "handler"
    if first in ("public", "private") and len(tokens) > 1 and \
       tokens[1] in ("handler", "command", "function", "getter", "setter"):
        return "handler"
    if is_script and first in SCRIPT_HANDLER_OPENERS:
        return "handler"
    if first == "unsafe":
        return "unsafe"
    if first == "repeat":
        return "repeat"
    if first == "try":
        return "try"                      # try ... catch ... finally ... end try
    if first in ("else", "catch", "finally"):
        return None                       # continuation, not a new block
    if first == "if" and tokens[-1] == "then":
        return "if"                       # block if; single-line if has code after `then`
    return None


def check_balance(path, stripped_lines, is_script, problems):
    stack = []   # list of (kind, lineno)
    for lineno, sline in enumerate(stripped_lines, start=1):
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", sline.lower())
        if not tokens:
            continue
        if tokens[0] == "end":
            what = tokens[1] if len(tokens) > 1 else ""
            if what in ("if", "repeat", "unsafe", "try", "library", "module", "widget"):
                if not stack or stack[-1][0] != what:
                    top = stack[-1][0] if stack else "nothing"
                    problems.append(Problem(
                        path, lineno,
                        f"`end {what}` closes a {what} block but the open block is {top}"))
                else:
                    stack.pop()
            else:
                # `end handler` (.lcb) or `end <handlername>` (.livecodescript)
                if not stack or stack[-1][0] != "handler":
                    top = stack[-1][0] if stack else "nothing"
                    problems.append(Problem(
                        path, lineno,
                        f"`end {what}` closes a handler but the open block is {top}"))
                else:
                    stack.pop()
            continue
        kind = classify_opener(tokens, is_script)
        if kind is not None:
            stack.append((kind, lineno))
    for kind, lineno in stack:
        problems.append(Problem(
            path, lineno, f"{kind} block opened here is never closed"))


def check_constants_before_use(path, stripped_lines, problems):
    decl_line = {}
    for lineno, sline in enumerate(stripped_lines, start=1):
        m = re.match(r"\s*constant\s+([A-Za-z_][A-Za-z0-9_]*)\s+is\b", sline)
        if m:
            name = m.group(1)
            decl_line.setdefault(name, lineno)
    for name, dline in decl_line.items():
        pattern = re.compile(r"\b" + re.escape(name) + r"\b")
        for lineno, sline in enumerate(stripped_lines, start=1):
            if lineno >= dline:
                break
            if pattern.search(sline):
                problems.append(Problem(
                    path, lineno,
                    f"constant `{name}` used before its declaration on line {dline}"))


def check_shadow_trap(path, stripped_lines, problems):
    seen = set()   # report each (name, line) once
    for lineno, sline in enumerate(stripped_lines, start=1):
        for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", sline):
            if ident[0] not in "tpsk":
                continue
            if ident == ident.lower():
                continue               # a bare lowercase keyword, not a prefixed name
            low = ident.lower()
            if low in RESERVED and (ident, lineno) not in seen:
                seen.add((ident, lineno))
                problems.append(Problem(
                    path, lineno,
                    f"name `{ident}` lowercases to the reserved token `{low}` "
                    f"(prefixed-token-shadow trap); choose a different stem"))


# Foreign types live in com.livecode.foreign; if a .lcb uses any of them it must
# `use` that module (a "not declared" compile error otherwise). textEncode /
# textDecode are NOT available to an LCB module (they are LiveCode Script only),
# so flag them in .lcb code. Both gaps cost a real OXT compile cycle.
FOREIGN_TYPES = {
    "pointer", "cbool", "cchar", "cuchar", "cschar", "cshort", "cushort",
    "cint", "cuint", "clong", "culong", "cfloat", "cdouble", "csize",
    "zstringutf8", "zstringutf16", "zstringnative", "naturalfloat", "naturaluint",
}


def check_lcb_imports(path, stripped_lines, problems):
    used = set()
    type_hit = None
    text_hits = []
    for lineno, sline in enumerate(stripped_lines, start=1):
        m = re.match(r"\s*use\s+([A-Za-z0-9_.]+)", sline)
        if m:
            used.add(m.group(1))
            continue
        for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", sline):
            low = ident.lower()
            if type_hit is None and low in FOREIGN_TYPES:
                type_hit = (lineno, ident)
            if ident in ("textEncode", "textDecode"):
                text_hits.append((lineno, ident))
    if type_hit is not None and "com.livecode.foreign" not in used:
        problems.append(Problem(
            path, type_hit[0],
            f"foreign type `{type_hit[1]}` used but `use com.livecode.foreign` "
            f"is missing (it will not be declared on an OXT compile)"))
    for lineno, ident in text_hits:
        problems.append(Problem(
            path, lineno,
            f"`{ident}` is a LiveCode Script function, not available to an LCB "
            f"module; keep text<->Data conversion in script or pass Data"))


def check_put_prepositions(path, stripped_lines, problems):
    """A `put` takes `into` OR `after`/`before`, never both. `put X into Y after Y`
    is malformed: the engine rejects the stray preposition ("can't find handler"
    / hint 'after'). This is statically catchable, so catch it before an OXT
    cycle does. Runs on string-stripped lines, so a literal 'after'/'into' inside
    a quoted string never trips it."""
    for lineno, sline in enumerate(stripped_lines, start=1):
        m = re.match(r"\s*(?:then\s+)?put\b(.*)", sline)
        if not m:
            continue
        rest = m.group(1)
        if re.search(r"\binto\b", rest) and re.search(r"\b(?:after|before)\b", rest):
            problems.append(Problem(
                path, lineno,
                "a `put` uses both `into` and `after`/`before`; use one "
                "(`put X into Y` to replace, or `put X after Y` to append)"))


def check_file(path, problems):
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    raw_lines = text.splitlines()
    code = strip_block_comments(text)
    stripped_lines = [strip_line(l) for l in code.splitlines()]
    is_script = path.endswith(".livecodescript")

    check_banned_chars(path, raw_lines, problems)
    check_balance(path, stripped_lines, is_script, problems)
    check_constants_before_use(path, stripped_lines, problems)
    check_shadow_trap(path, stripped_lines, problems)
    check_put_prepositions(path, stripped_lines, problems)
    if not is_script:
        check_lcb_imports(path, stripped_lines, problems)


def discover(root):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "build")]
        for name in filenames:
            if name.endswith(".lcb") or name.endswith(".livecodescript"):
                found.append(os.path.join(dirpath, name))
    return sorted(found)


def main(argv):
    targets = argv[1:] if len(argv) > 1 else discover(".")
    if not targets:
        print("check-livecodescript: no .lcb or .livecodescript files found")
        return 0

    problems = []
    for path in targets:
        check_file(path, problems)

    if problems:
        for p in sorted(problems, key=lambda x: (x.path, x.line)):
            print(p)
        print(f"\ncheck-livecodescript: {len(problems)} problem(s) in "
              f"{len(targets)} file(s)")
        return 1

    print(f"check-livecodescript: OK ({len(targets)} file(s) checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
