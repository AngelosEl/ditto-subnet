"""Language-aware comment and string-literal masking for untrusted source.

Every deterministic scanner in the screener reads a *masked* view of a file:
comments are blanked so prose cannot raise a lead or a malicious finding, and
string literals are blanked where an effect must be a real operation rather
than a word inside a prompt. Masking is therefore security-relevant in both
directions:

- masking too much erases real code, so a genuine finding loses its citations
  and can be demoted or cleared;
- masking too little leaves prose visible, so a comment can fabricate a
  confidence-1.0 malicious finding before the build.

A single C-style lexer applied to every file got both wrong: a Python
``'data/*.json'`` opened a block comment that blanked the rest of the file,
Python/shell/Dockerfile ``#`` comments stayed visible, and a Rust lifetime
(``<'a>``) desynchronized the string masker. Each language is now lexed by its
own rules, chosen from a small explicit table keyed by file name.

The module fails closed. A path whose language is not in the table, or a file
the lexer cannot bring to a clean end (an unterminated string or block comment,
unbalanced JavaScript nesting or JSX-like markup), is returned unchanged: more
stays visible to the scanners rather than less. Masking only ever replaces
characters with spaces and never touches a line break, so line numbers and
columns stay aligned with the raw source for every language.
"""

from __future__ import annotations

import bisect
import re
import tokenize
import warnings
from collections.abc import Callable, Iterator
from functools import lru_cache, partial

__all__ = [
    "CHAR_LITERAL",
    "language_for_path",
    "mask_comments",
    "mask_python_code",
    "mask_string_literals",
]

# A Go rune or Rust char literal: one character or one escape (``\n``,
# ``\xHH``, ``\u{...}``, Go ``\uXXXX`` / ``\UXXXXXXXX`` / octal). In Rust,
# anything else after an apostrophe is a lifetime or loop label.
CHAR_LITERAL = re.compile(
    r"'(?:[^'\\\n]|\\(?:u\{[0-9a-fA-F]{1,6}\}|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}"
    r"|U[0-9a-fA-F]{8}|[0-7]{3}|[^\n]))'"
)

_CODE = 0
_COMMENT = 1
_STRING = 2

# Anything but a character ``str.splitlines`` treats as a line boundary. Those
# are never replaced, so the masked view always has exactly the raw line count.
_BLANKABLE = re.compile(r"[^\n\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]")
_RUNS = {
    kind: re.compile(re.escape(bytes([kind])) + b"+") for kind in (_COMMENT, _STRING)
}

_LANGUAGE_BY_SUFFIX = {
    ".rs": "rust",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cc": "c",
    ".cpp": "c",
    ".cxx": "c",
    ".hh": "c",
    ".hpp": "c",
    ".hxx": "c",
    # JSX/TSX are deliberately absent: JSX text (``<p>Don't</p>``) is not
    # lexable without a JSX parser, so those files stay unmasked.
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".py": "python",
    ".pyi": "python",
    ".pyw": "python",
    ".pyx": "python",
    ".pxd": "python",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ksh": "shell",
    ".toml": "toml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".mk": "make",
    ".ini": "ini",
    ".cfg": "ini",
}
_LANGUAGE_BY_NAME = {
    "dockerfile": "dockerfile",
    "containerfile": "dockerfile",
    "go.mod": "go",
    "go.work": "go",
    "makefile": "make",
    "gnumakefile": "make",
    "pipfile": "toml",
    "cargo.lock": "toml",
    "poetry.lock": "toml",
    "uv.lock": "toml",
    ".env": "dotenv",
}
# Only these languages have string literals that are inert data. In shell,
# Dockerfile, and configuration formats a quoted word is routinely the command
# itself (``sh -c '...'``, ``"$(cat ...)"``, a ``[tool.*]`` script), so
# blanking it would erase the effect a scanner is looking for.
_STRING_MASKED_LANGUAGES = frozenset(
    {"rust", "go", "c", "javascript", "typescript", "python"}
)
# The kernel executes a script's ``#!`` line (``env -S`` accepts a whole
# command), so it is never masked as a comment.
_SHEBANG_LANGUAGES = frozenset({"python", "shell", "javascript", "typescript"})


def language_for_path(path: str) -> str | None:
    """Return the masking language for ``path``, or ``None`` when unknown."""
    name = path.rsplit("/", 1)[-1].casefold()
    language = _LANGUAGE_BY_NAME.get(name)
    if language is not None:
        return language
    if name.startswith(("dockerfile.", "containerfile.")) or name.endswith(
        (".dockerfile", ".containerfile")
    ):
        return "dockerfile"
    if name.startswith(("requirements", "constraints")) and name.endswith(".txt"):
        return "requirements"
    if name.startswith(".env."):
        return "dotenv"
    dot = name.rfind(".")
    return _LANGUAGE_BY_SUFFIX.get(name[dot:]) if dot > 0 else None


def mask_comments(text: str, path: str) -> str:
    """Blank comments in ``text`` by the rules of ``path``'s language.

    Strings, layout, and line count are preserved. Unknown languages and
    sources that do not lex cleanly are returned unchanged.
    """
    kinds = _kinds_for(text, path)
    return text if kinds is None else _blank(text, kinds, _COMMENT)


def mask_string_literals(text: str, path: str) -> str:
    """Blank string-literal text in ``text`` by the rules of ``path``'s language.

    Callers pass the comment-masked view. Only languages whose literals are
    inert data are masked; interpolated code (``f"{call()}"``, JavaScript
    ``${call()}``) stays visible. Everything else is returned unchanged.
    """
    if language_for_path(path) not in _STRING_MASKED_LANGUAGES:
        return text
    kinds = _kinds_for(text, path)
    return text if kinds is None else _blank(text, kinds, _STRING)


def mask_python_code(text: str) -> str | None:
    """Blank Python comments and literals, or ``None`` if it does not tokenize.

    For callers that skip sources they cannot tokenize rather than falling
    back to the approximate lexer.
    """
    kinds = _cached_python_tokens(text)
    if kinds is None:
        return None
    return _blank(_blank(text, kinds, _COMMENT), kinds, _STRING)


def _kinds_for(text: str, path: str) -> bytes | None:
    language = language_for_path(path)
    if language is None or not text:
        return None
    return _cached_kinds(text, language)


def _blank(text: str, kinds: bytes, kind: int) -> str:
    pieces: list[str] = []
    position = 0
    for run in _RUNS[kind].finditer(kinds):
        start, end = run.span()
        pieces.append(text[position:start])
        pieces.append(_BLANKABLE.sub(" ", text[start:end]))
        position = end
    if not pieces:
        return text
    pieces.append(text[position:])
    return "".join(pieces)


@lru_cache(maxsize=8)
def _cached_kinds(text: str, language: str) -> bytes | None:
    kinds = _LEXERS[language](text)
    if kinds is None:
        return None
    if language in _SHEBANG_LANGUAGES:
        _keep_shebang(text, kinds)
    return bytes(kinds)


@lru_cache(maxsize=4)
def _cached_python_tokens(text: str) -> bytes | None:
    kinds = _python_tokens(text)
    if kinds is None:
        return None
    _keep_shebang(text, kinds)
    return bytes(kinds)


def _keep_shebang(text: str, kinds: bytearray) -> None:
    if text.startswith("#!"):
        _mark(kinds, 0, _line_end(text, 0, _CR_LF), _CODE)


def _mark(kinds: bytearray, start: int, end: int, kind: int) -> None:
    end = min(end, len(kinds))
    if end > start:
        kinds[start:end] = bytes([kind]) * (end - start)


def _line_end(text: str, start: int, breaks: re.Pattern[str]) -> int:
    match = breaks.search(text, start)
    return len(text) if match is None else match.start()


_LF = re.compile(r"\n")
_CR_LF = re.compile(r"[\n\r]")
_JS_LINE_BREAK = re.compile(r"[\n\r\u2028\u2029]")


def _quoted(quote: str, *, breaks: str = "", escapes: bool = True) -> re.Pattern:
    """Match a literal body and its closing ``quote``, starting after the opener."""
    other = re.escape(quote + ("\\" if escapes else "") + breaks)
    if not escapes:
        return re.compile(rf"[^{other}]*{re.escape(quote)}")
    return re.compile(rf"[^{other}]*(?:\\[\s\S][^{other}]*)*{re.escape(quote)}")


_DOUBLE_MULTILINE = _quoted('"')
_DOUBLE_LF = _quoted('"', breaks="\n")
_SINGLE_LF = _quoted("'", breaks="\n")
_DOUBLE_CRLF = _quoted('"', breaks="\n\r")
_SINGLE_CRLF = _quoted("'", breaks="\n\r")
_SINGLE_LF_RAW = _quoted("'", breaks="\n", escapes=False)


# --- C family -----------------------------------------------------------------

_BLOCK_EDGE = re.compile(r"/\*|\*/")
_RUST_TOKEN = re.compile(r"//|/\*|\"|'|(?<!\w)(?:br|cr|r)(#*)\"")


def _nested_block_end(text: str, start: int) -> int | None:
    depth = 1
    for edge in _BLOCK_EDGE.finditer(text, start):
        depth += 1 if edge.group() == "/*" else -1
        if not depth:
            return edge.end()
    return None


def _lex_rust(text: str) -> bytearray | None:
    """Rust: nested block comments, raw strings, char literals vs lifetimes."""
    kinds = bytearray(len(text))
    index = 0
    while (token := _RUST_TOKEN.search(text, index)) is not None:
        start, value = token.start(), token.group()
        if value == "//":
            end = _line_end(text, start, _LF)
            _mark(kinds, start, end, _COMMENT)
        elif value == "/*":
            block_end = _nested_block_end(text, start + 2)
            if block_end is None:
                return None
            end = block_end
            _mark(kinds, start, end, _COMMENT)
        elif value == '"':
            body = _DOUBLE_MULTILINE.match(text, start + 1)
            if body is None:
                return None
            end = body.end()
            _mark(kinds, start, end, _STRING)
        elif value == "'":
            # ``'x'``, ``'\n'``, ``'\u{1F600}'`` are literals; ``'a`` in
            # ``<'a>``/``&'a str`` and ``'outer:`` labels are code.
            literal = CHAR_LITERAL.match(text, start)
            if literal is None:
                index = start + 1
                continue
            end = literal.end()
            _mark(kinds, start, end, _STRING)
        else:
            terminator = '"' + token.group(1)
            close = text.find(terminator, token.end())
            if close < 0:
                return None
            end = close + len(terminator)
            _mark(kinds, start, end, _STRING)
        index = end
    return kinds


_GO_TOKEN = re.compile(r"//|/\*|[\"'`]")


def _lex_go(text: str) -> bytearray | None:
    """Go: flat block comments, raw backtick strings, rune literals."""
    kinds = bytearray(len(text))
    index = 0
    while (token := _GO_TOKEN.search(text, index)) is not None:
        start, value = token.start(), token.group()
        if value == "//":
            end = _line_end(text, start, _LF)
            _mark(kinds, start, end, _COMMENT)
        elif value == "/*":
            close = text.find("*/", start + 2)
            if close < 0:
                return None
            end = close + 2
            _mark(kinds, start, end, _COMMENT)
        elif value == "`":
            close = text.find("`", start + 1)
            if close < 0:
                return None
            end = close + 1
            _mark(kinds, start, end, _STRING)
        else:
            literal = (
                _DOUBLE_LF.match(text, start + 1)
                if value == '"'
                else CHAR_LITERAL.match(text, start)
            )
            if literal is None:
                return None
            end = literal.end()
            _mark(kinds, start, end, _STRING)
        index = end
    return kinds


_C_SPLICE = re.compile(r"\\(?:\r\n|\n|\r)")
# A pp-number (``1'000'000``, ``0x1'F``, ``1e+5``) is consumed whole, so a C++14
# digit separator is never mistaken for a character literal.
_C_TOKEN = re.compile(
    r"//|/\*|(?<![\w.])\.?\d(?:[eEpP][+-]|'\w|[\w.])*"
    r"|(?<!\w)(?:u8|[uUL])?R\"|\"|'"
)
_CPP_RAW_DELIMITER = re.compile(r"([^\s()\\]{0,16})\(")


def _lex_c(text: str) -> bytearray | None:
    """C/C++: lexed after line splicing, so ``*\\<newline>/`` closes a comment."""
    if "\\" not in text or _C_SPLICE.search(text) is None:
        return _lex_c_logical(text)
    pieces: list[str] = []
    logical_starts: list[int] = []
    original_starts: list[int] = []
    logical_position = 0
    original_position = 0
    for splice in _C_SPLICE.finditer(text):
        piece = text[original_position : splice.start()]
        pieces.append(piece)
        logical_starts.append(logical_position)
        original_starts.append(original_position)
        logical_position += len(piece)
        original_position = splice.end()
    pieces.append(text[original_position:])
    logical_starts.append(logical_position)
    original_starts.append(original_position)
    logical_kinds = _lex_c_logical("".join(pieces))
    if logical_kinds is None:
        return None

    def original(logical_index: int) -> int:
        piece = bisect.bisect_right(logical_starts, logical_index) - 1
        return original_starts[piece] + logical_index - logical_starts[piece]

    kinds = bytearray(len(text))
    for kind in (_COMMENT, _STRING):
        for run in _RUNS[kind].finditer(logical_kinds):
            start, end = run.span()
            _mark(kinds, original(start), original(end - 1) + 1, kind)
    return kinds


def _lex_c_logical(text: str) -> bytearray | None:
    kinds = bytearray(len(text))
    index = 0
    while (token := _C_TOKEN.search(text, index)) is not None:
        start, value = token.start(), token.group()
        if value == "//":
            end = _line_end(text, start, _CR_LF)
            _mark(kinds, start, end, _COMMENT)
        elif value == "/*":
            close = text.find("*/", start + 2)
            if close < 0:
                return None
            end = close + 2
            _mark(kinds, start, end, _COMMENT)
        elif value.endswith('R"'):
            delimiter = _CPP_RAW_DELIMITER.match(text, token.end())
            if delimiter is None:
                # Not a raw string: an identifier ending in R, then a string.
                index = token.end() - 1
                continue
            terminator = ")" + delimiter.group(1) + '"'
            close = text.find(terminator, delimiter.end())
            if close < 0:
                return None
            end = close + len(terminator)
            _mark(kinds, start, end, _STRING)
        elif value[0] not in "\"'":
            end = token.end()  # a pp-number is code, skipped whole
        else:
            body = (_DOUBLE_CRLF if value == '"' else _SINGLE_CRLF).match(
                text, start + 1
            )
            if body is None:
                return None
            end = body.end()
            _mark(kinds, start, end, _STRING)
        index = end
    return kinds


# --- JavaScript / TypeScript --------------------------------------------------

_JS_TOKEN = re.compile(r"//|/\*|<!--|-->|[/'\"`(){}<]")
_JS_TEMPLATE_STOP = re.compile(r"\\[\s\S]|`|\$\{")
_JS_REGEX_BODY = re.compile(
    r"(?:[^\\/\[\n\r\u2028\u2029]|\\[^\n\r\u2028\u2029]"
    r"|\[(?:[^\]\\\n\r\u2028\u2029]|\\[^\n\r\u2028\u2029])*\])+/[\w$]*"
)
# Longer than any keyword the regex rule looks for.
_JS_MAX_WORD = 16
# Reserved words that are always followed by an expression.
_JS_EXPRESSION_KEYWORDS = frozenset(
    {
        "return",
        "typeof",
        "instanceof",
        "in",
        "new",
        "delete",
        "void",
        "throw",
        "case",
        "do",
        "else",
        "default",
        "extends",
    }
)
# Keywords in some contexts and plain identifiers in others (``let of = 4``,
# ``var yield``, ``var await`` in a script), so a slash after one either
# divides or opens a regular expression.
_JS_CONTEXTUAL_KEYWORDS = frozenset({"of", "yield", "await"})
_JS_CONDITION_KEYWORDS = frozenset({"if", "while", "for", "with"})
_JS_KEYWORDS = (
    _JS_EXPRESSION_KEYWORDS | _JS_CONTEXTUAL_KEYWORDS | _JS_CONDITION_KEYWORDS
)
_JS_JSX_START = re.compile(r"[A-Za-z_$>]")


def _lex_javascript(text: str, *, typescript: bool = False) -> bytearray | None:
    """JavaScript/TypeScript: strings, nested templates, regex literals.

    A ``/`` begins a regular expression only where an expression may start;
    the usual previous-token rule decides it, including ``)`` that closes an
    ``if``/``while``/``for`` condition. Where that rule cannot decide (after
    a ``}`` that may end a block or an object literal, a contextual keyword,
    ``++``/``--``, a TypeScript ``!`` or ``>``), a guess would let a crafted
    line fold real code into a regular expression, string, or comment, so the
    file is left unmasked. So is any construct that cannot be closed on a
    valid program (a string or regular expression reaching a line end,
    unbalanced brackets, a JSX-looking ``<Tag``) and any HTML-like comment
    (``<!--``, ``-->``), which a script reads as a comment and a module as
    operators.
    """
    kinds = bytearray(len(text))
    # Frames: "(" / "(if" for parentheses, "(?" after ``await`` (a call or a
    # ``for await`` head), "{" for braces, "${" for template substitutions
    # whose closing brace resumes the template literal.
    frames: list[str] = []
    # True where a regular expression may start, False where a slash divides,
    # None where the preceding code does not decide.
    expression_start: bool | None = True
    previous_word = ""
    # Whether the code before ``index`` (comments aside) ends in a member-access
    # dot, so a following keyword is a property name; None if it may be a
    # number's decimal point instead.
    after_dot: bool | None = False
    index = 0
    if text.startswith("#!"):
        # An interpreter line, not JavaScript; see ``_SHEBANG_LANGUAGES``.
        index = _line_end(text, 0, _JS_LINE_BREAK)
    while True:
        token = _JS_TOKEN.search(text, index)
        if token is None:
            return None if frames else kinds
        start, value = token.start(), token.group()
        code = text[index:start].rstrip()
        if code:
            expression_start, previous_word = _js_state_after(
                code, after_dot, expression_start, typescript
            )
            after_dot = _js_member_dot(code)
        end = start + 1
        if value == "//":
            end = _line_end(text, start, _JS_LINE_BREAK)
            _mark(kinds, start, end, _COMMENT)
            index = end
            continue
        if value == "/*":
            close = text.find("*/", start + 2)
            if close < 0:
                return None
            end = close + 2
            _mark(kinds, start, end, _COMMENT)
            index = end
            continue
        if value in {"<!--", "-->"}:
            return None
        after_dot = False
        word, previous_word = previous_word, ""
        if value == "/":
            if expression_start is None:
                return None
            if expression_start:
                # Where an expression starts, ``/`` can only open a regular
                # expression. One that does not close on its line means the
                # token rule misjudged the code (and retrying per slash would
                # be quadratic), so the file is left unmasked.
                regex = _JS_REGEX_BODY.match(text, start + 1)
                if regex is None:
                    return None
                end = regex.end()
                expression_start = False
            else:
                expression_start = True
        elif value in {"'", '"'}:
            body = (_SINGLE_CRLF if value == "'" else _DOUBLE_CRLF).match(
                text, start + 1
            )
            if body is None:
                return None
            end = body.end()
            _mark(kinds, start, end, _STRING)
            expression_start = False
        elif value == "`" or (value == "}" and frames and frames[-1] == "${"):
            if value == "}":
                frames.pop()
                literal_start = start + 1
            else:
                literal_start = start
            stop = _js_template_stop(text, start + 1)
            if stop is None:
                return None
            if text.startswith("`", stop):
                end = stop + 1
                _mark(kinds, literal_start, end, _STRING)
                expression_start = False
            else:
                end = stop + 2
                _mark(kinds, literal_start, stop, _STRING)
                frames.append("${")
                expression_start = True
        elif value == "(":
            if word in _JS_CONDITION_KEYWORDS:
                frames.append("(if")
            else:
                frames.append("(?" if word == "await" else "(")
            expression_start = True
        elif value == ")":
            if not frames or not frames[-1].startswith("("):
                return None
            closed = frames.pop()
            expression_start = {"(if": True, "(?": None}.get(closed, False)
        elif value == "{":
            frames.append("{")
            expression_start = True
        elif value == "}":
            if not frames or frames.pop() != "{":
                return None
            # A block ends before a statement, where a slash opens a regular
            # expression; an object literal or function expression ends an
            # operand, where it divides.
            expression_start = None
        elif value == "<":
            if expression_start is not False and _JS_JSX_START.match(text, start + 1):
                return None
            expression_start = True
        index = end


def _js_template_stop(text: str, start: int) -> int | None:
    index = start
    while (stop := _JS_TEMPLATE_STOP.search(text, index)) is not None:
        if stop.group().startswith("\\"):
            index = stop.end()
            continue
        return stop.start()
    return None


def _js_state_after(
    code: str, after_dot: bool | None, previous: bool | None, typescript: bool
) -> tuple[bool | None, str]:
    """Return (a regex may start next, trailing identifier) after ``code``.

    ``after_dot`` and ``previous`` describe what preceded ``code``: whether it
    ended in a member dot, and whether an expression could start there.
    """
    last = code[-1]
    if not _js_word_char(last):
        if last == "]":
            return False, ""
        if last in "+-":
            # ``+``/``-`` expect an operand. ``++``/``--`` end one as postfix
            # operators but start one as prefix operators after a line break.
            run = len(code) - len(code.rstrip(last))
            return (True if run == 1 else None), ""
        if typescript and last == ">" and not code.endswith("=>"):
            # ``f<T> / x`` divides an instantiation expression.
            return None, ""
        if typescript and last == "!":
            return _ts_state_after_bang(code, after_dot, previous), ""
        return True, ""
    start = len(code) - 1
    while start > 0 and _js_word_char(code[start - 1]):
        start -= 1
        if len(code) - start > _JS_MAX_WORD:
            return False, ""
    name = code[start:]
    if name not in _JS_KEYWORDS:
        return False, name
    if start and code[start - 1] == "#":
        # A private name (``this.#return``) is an operand.
        return False, ""
    before = code[:start]
    member = _js_member_dot(before) if before.strip() else after_dot
    if member is None:
        return None, ""
    if member:
        # A property named like a keyword (``obj.return``) is an operand.
        return False, ""
    if name in _JS_CONTEXTUAL_KEYWORDS:
        return None, name
    return name in _JS_EXPRESSION_KEYWORDS, name


def _ts_state_after_bang(
    code: str, after_dot: bool | None, previous: bool | None
) -> bool | None:
    """TypeScript ``!`` is a prefix (``!/x/``) or a non-null postfix (``x!``)."""
    before = code.rstrip("!").rstrip()
    if not before:
        return True if previous is True else None
    if not (_js_word_char(before[-1]) or before[-1] == "]"):
        return True
    state, _ = _js_state_after(before, after_dot, previous, True)
    return True if state is True else None


def _js_member_dot(code: str) -> bool | None:
    """Whether ``code`` ends in a member-access dot (None: maybe a number's)."""
    code = code.rstrip()
    if not code.endswith(".") or code.endswith("..."):
        return False
    return None if len(code) > 1 and code[-2].isdigit() else True


def _js_word_char(char: str) -> bool:
    return char.isalnum() or char in "_$"


# --- Python -------------------------------------------------------------------

_PY_NEWLINE = re.compile(r"\r\n|\r|\n")
_PY_FSTRING_START = frozenset(
    getattr(tokenize, name)
    for name in ("FSTRING_START", "TSTRING_START")
    if hasattr(tokenize, name)
)
_PY_FSTRING_END = frozenset(
    getattr(tokenize, name)
    for name in ("FSTRING_END", "TSTRING_END")
    if hasattr(tokenize, name)
)
_PY_FSTRING_PARTS = frozenset(
    getattr(tokenize, name)
    for name in ("FSTRING_MIDDLE", "TSTRING_MIDDLE")
    if hasattr(tokenize, name)
)
_PY_LAYOUT = frozenset(
    {
        tokenize.NEWLINE,
        tokenize.NL,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.ENDMARKER,
    }
)
_PY_FALLBACK_TOKEN = re.compile(r"#|'''|\"\"\"|'|\"")
_PY_TRIPLE_STOP = {q: re.compile(r"\\[\s\S]|" + q) for q in ("'''", '"""')}


class _TokenMismatch(Exception):
    """tokenize reported a position that does not match the source text."""


def _lex_python(text: str) -> bytearray | None:
    """Python: ``tokenize`` for exact comments, strings, and f-string fields.

    ``//`` and ``/*`` are never comment syntax in Python. If the source does
    not tokenize, a hash-comment lexer that honors quotes and triple quotes is
    used instead; the C lexer never is.
    """
    kinds = _python_tokens(text)
    return kinds if kinds is not None else _python_fallback(text)


def _python_tokens(text: str) -> bytearray | None:
    # Python treats ``\r\n``, ``\r``, and ``\n`` as newlines. Split on exactly
    # those so tokenize rows map back to raw offsets, whatever else
    # ``str.splitlines`` might consider a boundary.
    lines: list[tuple[int, str]] = []
    position = 0
    for newline in _PY_NEWLINE.finditer(text):
        lines.append((position, text[position : newline.start()]))
        position = newline.end()
    if position < len(text):
        lines.append((position, text[position:]))
    feed = iter([line + "\n" for _, line in lines])

    def offset(row: int, column: int) -> int:
        start, line = lines[row - 1]
        if column > len(line):
            raise _TokenMismatch
        return start + column

    fstrings: list[tuple[int, int]] = []
    open_fstrings: list[int] = []
    code: list[tuple[int, int]] = []
    strings: list[tuple[int, int]] = []
    comments: list[tuple[int, int]] = []
    try:
        for token in _quiet_tokens(feed):
            kind = token.type
            if kind in _PY_LAYOUT or kind in _PY_FSTRING_PARTS:
                continue
            if token.start[0] > len(lines) or token.end[0] > len(lines):
                raise _TokenMismatch
            span = (offset(*token.start), offset(*token.end))
            if _PY_NEWLINE.sub("\n", text[span[0] : span[1]]) != token.string:
                raise _TokenMismatch
            if kind in _PY_FSTRING_START:
                open_fstrings.append(span[0])
            elif kind in _PY_FSTRING_END:
                if not open_fstrings:
                    raise _TokenMismatch
                fstrings.append((open_fstrings.pop(), span[1]))
            elif kind == tokenize.STRING:
                strings.append(span)
            elif kind == tokenize.COMMENT:
                comments.append(span)
            elif open_fstrings:
                code.append(span)
    except (tokenize.TokenError, SyntaxError, _TokenMismatch):
        return None
    if open_fstrings:
        return None
    kinds = bytearray(len(text))
    # An f-string is literal text except its replacement fields, which are
    # code; nested literals and comments inside a field keep their own kind.
    for spans, kind in (
        (fstrings, _STRING),
        (code, _CODE),
        (strings, _STRING),
        (comments, _COMMENT),
    ):
        for start, end in spans:
            _mark(kinds, start, end, kind)
    return kinds


def _quiet_tokens(feed: Iterator[str]) -> Iterator[tokenize.TokenInfo]:
    # Invalid escapes in submitted source are not screener diagnostics.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        warnings.simplefilter("ignore", DeprecationWarning)
        yield from tokenize.generate_tokens(lambda: next(feed, ""))


def _python_fallback(text: str) -> bytearray | None:
    kinds = bytearray(len(text))
    index = 0
    while (token := _PY_FALLBACK_TOKEN.search(text, index)) is not None:
        start, value = token.start(), token.group()
        if value == "#":
            end = _line_end(text, start, _CR_LF)
            _mark(kinds, start, end, _COMMENT)
        elif len(value) == 3:
            stop_pattern = _PY_TRIPLE_STOP[value]
            cursor = start + 3
            while (stop := stop_pattern.search(text, cursor)) is not None:
                if stop.group() == value:
                    break
                cursor = stop.end()
            if stop is None:
                return None
            end = stop.end()
            _mark(kinds, start, end, _STRING)
        else:
            body = (_SINGLE_CRLF if value == "'" else _DOUBLE_CRLF).match(
                text, start + 1
            )
            if body is None:
                return None
            end = body.end()
            _mark(kinds, start, end, _STRING)
        index = end
    return kinds


# --- Shell --------------------------------------------------------------------

_SH_TOKEN = re.compile(
    r"\\[\s\S]|#|\$'|\$\(\(|\$\(|\$\{|\$\[|\(\(|['\"`(){}]|<<-?|\n"
    r"|(?<![^\s;&|(])(?:case|esac)(?![^\s;&|)])"
)
_SH_WORD_BREAK = frozenset(" \t\n;&|()<>")
_SH_HEREDOC_WORD = re.compile(
    r"[ \t]*((?:[^\s;&|()<>'\"\\]|\\.|'[^'\n]*'|\"[^\"\n]*\")+)"
)
_SH_ANSI_C = _quoted("'")


class _ShellFrame:
    __slots__ = ("depth", "kind", "quoted")

    def __init__(self, kind: str, *, quoted: bool = False) -> None:
        # "top", "cmd" ($(...)), "dq", "bt" (`...`), "param" (${...}), and
        # "arith" ($((...)) and ((...)), where ``<<`` shifts and ``#`` is text).
        self.kind = kind
        self.depth = 0
        self.quoted = quoted


def _lex_shell(text: str) -> bytearray | None:
    """POSIX/bash: ``#`` starts a comment only at the start of an unquoted word.

    Quotes, ``$(...)``, backticks, ``${...}`` (where ``#`` is an operator),
    arithmetic (where ``<<`` is a shift) and here-document bodies are tracked
    so a ``#`` inside any of them is never read as a comment. Here-document
    bodies are left verbatim: they are often the script that actually runs.

    bash parses and runs a script one command at a time, so text after an
    ``exit`` can rebalance any quote or bracket this lexer tracks without ever
    running. Where the lexer cannot tell how bash reads a construct (``$[``,
    ``<<`` inside an assignment subscript, a ``case`` word inside ``$(...)``,
    ``$((`` that turns out to hold a subshell), the file is left unmasked
    rather than guessed at.
    """
    kinds = bytearray(len(text))
    frames = [_ShellFrame("top")]
    heredocs: list[tuple[str, bool]] = []
    index = 0
    while (token := _SH_TOKEN.search(text, index)) is not None:
        start, value = token.start(), token.group()
        end = token.end()
        frame = frames[-1]
        if value.startswith("\\"):
            index = end
            continue
        if value == "$[":
            # Legacy arithmetic: ``<<`` inside it is a shift.
            return None
        if frame.kind == "dq":
            if value == '"':
                frames.pop()
            elif value == "$((":
                frames.append(_ShellFrame("arith"))
            elif value == "$(":
                frames.append(_ShellFrame("cmd"))
            elif value == "${":
                frames.append(_ShellFrame("param", quoted=True))
            elif value == "`":
                frames.append(_ShellFrame("bt"))
            else:
                end = start + 1
            index = end
            continue
        if value == '"':
            frames.append(_ShellFrame("dq"))
        elif value == "'" and not (frame.kind == "param" and frame.quoted):
            close = text.find("'", start + 1)
            if close < 0:
                return None
            end = close + 1
        elif value == "$'":
            body = _SH_ANSI_C.match(text, end)
            if body is None:
                return None
            end = body.end()
        elif value == "$((":
            frames.append(_ShellFrame("arith"))
        elif value == "$(":
            frames.append(_ShellFrame("cmd"))
        elif value == "${":
            frames.append(_ShellFrame("param"))
        elif value == "`":
            if frame.kind == "bt":
                frames.pop()
            else:
                frames.append(_ShellFrame("bt"))
        elif frame.kind == "param":
            if value == "{":
                frame.depth += 1
            elif value == "}":
                if frame.depth:
                    frame.depth -= 1
                else:
                    frames.pop()
            else:
                end = start + 1
        elif frame.kind == "arith":
            if value in {"(", "(("}:
                frame.depth += len(value)
            elif value == ")":
                if frame.depth:
                    frame.depth -= 1
                elif text.startswith(")", end):
                    frames.pop()
                    end += 1
                else:
                    # ``$((cmd) )`` is a command substitution holding a
                    # subshell after all.
                    return None
            else:
                end = start + 1
        elif value == "((":
            frames.append(_ShellFrame("arith"))
        elif value == "#":
            if _sh_word_start(text, start):
                end = _line_end(text, start, _LF)
                if frame.kind == "bt":
                    backtick = text.find("`", start, end)
                    end = end if backtick < 0 else backtick
                _mark(kinds, start, end, _COMMENT)
        elif value == "(":
            frame.depth += 1
        elif value == ")":
            if frame.depth:
                frame.depth -= 1
            elif frame.kind == "cmd":
                frames.pop()
        elif value in {"case", "esac"}:
            if frame.kind == "cmd":
                # A pattern's ``)`` does not close ``$(``, but a ``case`` word
                # may also be an argument (``$(echo case)``).
                return None
        elif value.startswith("<<"):
            if text.startswith("<", end):
                end += 1
            elif _sh_in_subscript(text, start):
                # ``a[1<<2]=x`` shifts inside an assignment subscript.
                return None
            else:
                word = _SH_HEREDOC_WORD.match(text, end)
                if word is not None:
                    delimiter = re.sub(r"['\"\\]", "", word.group(1))
                    if delimiter:
                        heredocs.append((delimiter, value == "<<-"))
                    end = word.end()
        elif value == "\n" and heredocs:
            end = _skip_heredoc_bodies(text, end, heredocs)
            heredocs.clear()
        index = end
    return kinds if len(frames) == 1 else None


def _sh_in_subscript(text: str, index: int) -> bool:
    """Whether ``text[index]`` follows an unclosed ``[`` in the same word."""
    word_start = index
    while word_start > 0 and text[word_start - 1] not in _SH_WORD_BREAK:
        word_start -= 1
    word = text[word_start:index]
    return word.count("[") > word.count("]")


def _sh_word_start(text: str, index: int) -> bool:
    """Whether ``text[index]`` begins a word; an escaped blank joins words."""
    if index == 0:
        return True
    if text[index - 1] not in _SH_WORD_BREAK:
        return False
    backslashes = 0
    cursor = index - 2
    while cursor >= 0 and text[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 0


def _skip_heredoc_bodies(
    text: str, start: int, heredocs: list[tuple[str, bool]]
) -> int:
    """Return the offset after every pending here-document body."""
    position = start
    for delimiter, strip_tabs in heredocs:
        while position < len(text):
            newline = text.find("\n", position)
            line_end = len(text) if newline < 0 else newline
            line = text[position:line_end]
            position = line_end + 1
            if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                break
    return min(position, len(text))


# --- Dockerfile ----------------------------------------------------------------

_DOCKER_HEREDOC_OPEN = re.compile(r"(?<!<)<<(-?)(?!<)")
# The rest of a shell word after ``<<``: BuildKit ends it at an unquoted blank
# and removes its quotes. A backslash, ``$`` or ``<`` stops the match.
_DOCKER_HEREDOC_NAME = re.compile(r"(?:[^\s'\"\\<$]|'[^'\n]*'|\"[^\"\\$\n]*\")+")
_DOCKER_HEREDOC_QUOTE = re.compile(r"'([^']*)'|\"([^\"]*)\"")
_DOCKER_DIRECTIVE = re.compile(r"#[ \t]*(?:syntax|escape|check)[ \t]*=", re.I)
_DOCKER_INSTRUCTION = re.compile(r"([A-Za-z]+)(?=[ \t]|$)")
_DOCKER_SHELL_FORM = frozenset({"RUN", "CMD", "ENTRYPOINT"})
_DOCKER_EXEC_FORM = re.compile(r"(?:[ \t]+--\S+)*[ \t]*\[")
# A SHELL instruction or an escape directive changes how RUN text is read, so
# shell comments inside RUN/CMD/ENTRYPOINT are then left visible.
_DOCKER_OTHER_SHELL = re.compile(
    r"^[ \t]*(?:shell\b|#[ \t]*escape[ \t]*=)", re.I | re.M
)


def _lex_dockerfile(text: str) -> bytearray | None:
    """Dockerfile: whole-line ``#`` comments, plus shell comments in RUN.

    Docker strips a line whose first non-blank character is ``#``, even inside
    a continued instruction; elsewhere ``#`` is an argument. Shell-form
    RUN/CMD/ENTRYPOINT text goes to ``/bin/sh``, so the shell lexer decides its
    trailing comments. Parser directives at the top (``# syntax=`` selects the
    BuildKit frontend) and here-document bodies (script content) stay visible.
    A here-document whose delimiter BuildKit may read differently leaves the
    file unmasked, since ending its body early would blank script lines.
    """
    kinds = bytearray(len(text))
    lines = _lf_lines(text)
    shell_rules = _DOCKER_OTHER_SHELL.search(text) is None
    directives = True
    index = 0
    while index < len(lines):
        start, line = lines[index]
        index += 1
        content = line.removesuffix("\r")
        body = content.lstrip(" \t")
        if body.startswith("#"):
            if not (directives and _DOCKER_DIRECTIVE.match(body)):
                directives = False
                comment = start + len(content) - len(body)
                _mark(kinds, comment, start + len(content), _COMMENT)
            continue
        directives = False
        if not body:
            continue
        end = start + len(content)
        physical = content
        heredoc = False
        while True:
            markers = _dockerfile_heredocs(physical)
            if markers is None:
                return None
            if markers:
                heredoc = True
                index = _skip_dockerfile_heredocs(lines, index, markers)
                break
            if not physical.rstrip(" \t").endswith("\\") or index >= len(lines):
                break
            next_start, next_line = lines[index]
            index += 1
            physical = next_line.removesuffix("\r")
            stripped = physical.lstrip(" \t")
            if stripped.startswith("#"):
                comment = next_start + len(physical) - len(stripped)
                _mark(kinds, comment, next_start + len(physical), _COMMENT)
            if not stripped or stripped.startswith("#"):
                # Docker drops the line; the instruction stays open.
                physical = "\\"
                continue
            end = next_start + len(physical)
        instruction = _DOCKER_INSTRUCTION.match(body)
        if (
            heredoc
            or not shell_rules
            or instruction is None
            or instruction.group(1).upper() not in _DOCKER_SHELL_FORM
        ):
            continue
        argument_start = start + len(content) - len(body) + instruction.end()
        argument = text[argument_start:end]
        if _DOCKER_EXEC_FORM.match(argument):
            continue
        shell = _lex_shell(argument)
        if shell is None:
            continue
        for run in _RUNS[_COMMENT].finditer(shell):
            _mark(
                kinds,
                argument_start + run.start(),
                argument_start + run.end(),
                _COMMENT,
            )
    return kinds


def _dockerfile_heredocs(line: str) -> list[tuple[str, bool]] | None:
    """The (delimiter, strip tabs) of each here-document ``line`` opens.

    BuildKit opens one at a shell word ``<<NAME`` (optionally after
    file-descriptor digits, with ``-`` to strip tabs) or at a bare ``<<``
    followed by blanks and a NAME word, and ends it at a line equal to NAME
    with quotes removed (``<<"E F"`` at ``E F``, ``<< EOF;x`` at ``EOF;x``).
    Only a ``<<`` that follows another printable character in the same word
    (``cat<<EOF``) is ruled out; any other opener counts, because skipping
    lines that are not a body only leaves them visible. None means a delimiter
    this lexer cannot predict (escapes, variables, an unclosed quote, unusual
    blanks).
    """
    heredocs: list[tuple[str, bool]] = []
    for opener in _DOCKER_HEREDOC_OPEN.finditer(line):
        before = opener.start()
        while before and line[before - 1].isascii() and line[before - 1].isdigit():
            before -= 1
        if before:
            previous = line[before - 1]
            if previous.isascii() and previous.isprintable() and previous != " ":
                continue
        cursor = opener.end()
        while cursor < len(line) and line[cursor] in " \t":
            cursor += 1
        name = _DOCKER_HEREDOC_NAME.match(line, cursor)
        stop = cursor if name is None else name.end()
        if stop < len(line) and line[stop] not in " \t":
            return None
        if name is None:
            continue
        delimiter = _DOCKER_HEREDOC_QUOTE.sub(
            lambda quoted: quoted.group(1) or quoted.group(2) or "", name.group()
        )
        if delimiter:
            heredocs.append((delimiter, opener.group(1) == "-"))
    return heredocs


def _skip_dockerfile_heredocs(
    lines: list[tuple[int, str]], index: int, markers: list[tuple[str, bool]]
) -> int:
    """Return the index of the first line after every here-document body."""
    for delimiter, strip_tabs in markers:
        while index < len(lines):
            candidate = lines[index][1].removesuffix("\r")
            index += 1
            if (candidate.lstrip("\t") if strip_tabs else candidate) == delimiter:
                break
    return index


def _lf_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    position = 0
    while position <= len(text):
        newline = text.find("\n", position)
        if newline < 0:
            if position < len(text):
                lines.append((position, text[position:]))
            break
        lines.append((position, text[position:newline]))
        position = newline + 1
    return lines


# --- Configuration formats ------------------------------------------------------

_TOML_TOKEN = re.compile(r"#|\"\"\"|'''|\"|'")
_TOML_BASIC_STOP = re.compile(r'\\[\s\S]|"""')


def _lex_toml(text: str) -> bytearray | None:
    """TOML: ``#`` outside basic, literal, and multi-line strings."""
    kinds = bytearray(len(text))
    index = 0
    while (token := _TOML_TOKEN.search(text, index)) is not None:
        start, value = token.start(), token.group()
        if value == "#":
            end = _line_end(text, start, _LF)
            _mark(kinds, start, end, _COMMENT)
        elif len(value) == 3:
            if value == "'''":
                close = text.find("'''", start + 3)
            else:
                cursor = start + 3
                close = -1
                while (stop := _TOML_BASIC_STOP.search(text, cursor)) is not None:
                    if stop.group() == '"""':
                        close = stop.start()
                        break
                    cursor = stop.end()
            if close < 0:
                return None
            end = close + 3
            # A closing delimiter may be preceded by up to two more quotes.
            extra = 0
            while extra < 2 and text.startswith(value[0], end):
                end += 1
                extra += 1
        else:
            body = (_DOUBLE_LF if value == '"' else _SINGLE_LF_RAW).match(
                text, start + 1
            )
            if body is None:
                return None
            end = body.end()
        index = end
    return kinds


_YAML_BLOCK_SCALAR = re.compile(r"(?:^|[\s:-])[|>][0-9+-]*$")
_YAML_DOCUMENT_BLOCK = re.compile(r"^(?:---[ \t]+)?(?:[!&][^\s]*[ \t]+)*[|>][0-9+-]*$")


def _lex_yaml(text: str) -> bytearray | None:
    """YAML: ``#`` after whitespace outside quoted and block scalars.

    Quotes only open a scalar where a scalar may begin, so ``it's`` in a plain
    scalar is text. Block scalars (``run: |``) are left verbatim: their lines
    are content, often a script, never YAML comments.
    """
    kinds = bytearray(len(text))
    quote = ""
    block_indent: int | None = None
    for start, raw in _lf_lines(text):
        line = raw.removesuffix("\r")
        indent = len(line) - len(line.lstrip(" "))
        if block_indent is not None:
            if block_indent < 0:
                if not line.startswith(("---", "...")):
                    continue
            elif not line.strip() or indent > block_indent:
                continue
            block_indent = None
        scalar_start = True
        comment = len(line)
        cursor = 0
        while cursor < len(line):
            char = line[cursor]
            if quote:
                if quote == '"' and char == "\\":
                    cursor += 2
                    continue
                if char == quote:
                    if quote == "'" and line.startswith("'", cursor + 1):
                        cursor += 2
                        continue
                    quote = ""
                    scalar_start = False
                cursor += 1
                continue
            if char == "#" and (cursor == 0 or line[cursor - 1] in " \t"):
                comment = cursor
                break
            if char in " \t":
                pass
            elif char in "'\"" and scalar_start:
                quote = char
            elif char in "[{," or (
                char in "-?:" and (cursor + 1 == len(line) or line[cursor + 1] in " \t")
            ):
                scalar_start = True
            elif char in "&!" and scalar_start:
                while cursor + 1 < len(line) and line[cursor + 1] not in " \t":
                    cursor += 1
            else:
                scalar_start = False
            cursor += 1
        _mark(kinds, start + comment, start + len(line), _COMMENT)
        code = line[:comment].rstrip()
        if not quote and _YAML_BLOCK_SCALAR.search(code):
            block_indent = -1 if _YAML_DOCUMENT_BLOCK.match(code) else indent
    return None if quote else kinds


_MAKE_REFERENCE_CLOSE = {"(": ")", "{": "}"}
_MAKE_DEFINE = re.compile(r"^\s*(?:(?:override|export)\s+)*define\b")
_MAKE_ENDEF = re.compile(r"^\s*endef\b")


def _lex_make(text: str) -> bytearray:
    """Make: ``#`` outside recipes, ``define`` bodies, and ``$(...)`` calls.

    Make does not honor quotes, so a ``#`` in ``VAR = "a # b"`` is a comment,
    but within a variable reference or function call it is literal. Recipe
    lines belong to the shell and are left verbatim.
    """
    kinds = bytearray(len(text))
    references: list[str] = []
    defines = 0
    recipe = False
    continued = False
    for start, raw in _lf_lines(text):
        line = raw.removesuffix("\r")
        continues = (len(line) - len(line.rstrip("\\"))) % 2 == 1
        if defines:
            if _MAKE_DEFINE.match(line):
                defines += 1
            elif _MAKE_ENDEF.match(line):
                defines -= 1
            continue
        if not continued:
            references.clear()
            recipe = line.startswith("\t")
            if not recipe and _MAKE_DEFINE.match(line):
                defines = 1
                continue
        continued = continues
        if recipe:
            continue
        cursor = 0
        while cursor < len(line):
            char = line[cursor]
            if char == "\\":
                cursor += 2
                continue
            if char == "$":
                opener = line[cursor + 1 : cursor + 2]
                if opener in _MAKE_REFERENCE_CLOSE:
                    references.append(_MAKE_REFERENCE_CLOSE[opener])
                cursor += 2
                continue
            if references:
                if char == references[-1]:
                    references.pop()
                elif char in _MAKE_REFERENCE_CLOSE:
                    references.append(_MAKE_REFERENCE_CLOSE[char])
            elif char == "#":
                # Make continues a comment across a trailing backslash; the
                # next line is left visible rather than guessed at.
                _mark(kinds, start + cursor, start + len(line), _COMMENT)
                continued = False
                break
            cursor += 1
    return kinds


def _regex_comments(pattern: re.Pattern[str]) -> Callable[[str], bytearray]:
    def lex(text: str) -> bytearray:
        kinds = bytearray(len(text))
        for match in pattern.finditer(text):
            _mark(kinds, match.start(1), match.end(1), _COMMENT)
        return kinds

    return lex


# pip: a ``#`` at the start of a line or after whitespace; no quoting.
_lex_requirements = _regex_comments(re.compile(r"(?:^|(?<=[ \t]))(#[^\n]*)", re.M))
# Consumers disagree about inline ``#`` in dotenv/INI values, so only whole-line
# comments are masked.
_lex_dotenv = _regex_comments(re.compile(r"^[ \t]*(#[^\n]*)", re.M))
_lex_ini = _regex_comments(re.compile(r"^[ \t]*([#;][^\n]*)", re.M))


_LEXERS: dict[str, Callable[[str], bytearray | None]] = {
    "rust": _lex_rust,
    "go": _lex_go,
    "c": _lex_c,
    "javascript": _lex_javascript,
    "typescript": partial(_lex_javascript, typescript=True),
    "python": _lex_python,
    "shell": _lex_shell,
    "dockerfile": _lex_dockerfile,
    "toml": _lex_toml,
    "yaml": _lex_yaml,
    "make": _lex_make,
    "requirements": _lex_requirements,
    "dotenv": _lex_dotenv,
    "ini": _lex_ini,
}
