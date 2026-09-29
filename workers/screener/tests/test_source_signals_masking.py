"""Language-aware comment and string masking (#2457).

Masking feeds every deterministic scanner, so it must fail in neither
direction: foreign comment syntax must not erase real code, and a language's
own comments must not fabricate findings.
"""

from __future__ import annotations

import random
import time

import pytest

from ditto_screener.source_masking import language_for_path
from ditto_screener.source_signals import (
    find_decisive_malicious_source,
    mask_comments,
    mask_string_literals,
)

_LINE_BREAKS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85  "


def _blank(text: str, *parts: str) -> str:
    """Replace each unique ``part`` of ``text`` with spaces, keeping line breaks."""
    for part in parts:
        assert text.count(part) == 1, part
        blanked = "".join(char if char in _LINE_BREAKS else " " for char in part)
        text = text.replace(part, blanked)
    return text


# (path, raw, comment text, string-literal text). The comment view blanks the
# comments; the string view additionally blanks the literals.
_LANGUAGE_TABLE = [
    pytest.param(
        "src/agent.py",
        "files = glob.glob('data/*.json')  # see /* notes\n"
        "half = total // 2\n"
        "s = f'{load(x)} done'\n",
        ("# see /* notes",),
        ("'data/*.json'", "f'", " done'"),
        id="python",
    ),
    pytest.param(
        "src/main.rs",
        "fn pick<'a>(x: &'a str) -> char { '\"' } // c\n"
        'let r = r#"*/ // "#; /* a /* b */ c */ run();\n'
        "let s = \"don't // read\"; let e = '\\u{1F600}'; let l = '/';\n",
        ("// c", "/* a /* b */ c */"),
        ("'\"'", 'r#"*/ // "#', '"don\'t // read"', "'\\u{1F600}'", "'/'"),
        id="rust",
    ),
    pytest.param(
        "cmd/main.go",
        "x := `http://a/*` // c\ny := '\\''; z := \"a//b\" /* d */\n",
        ("// c", "/* d */"),
        ("`http://a/*`", "'\\''", '"a//b"'),
        id="go",
    ),
    pytest.param(
        "csrc/shim.c",
        "int n = 1'000; char q = '\"'; /* a *\\\n/ run(); // c\n"
        'const char *s = R"x(")x";\n',
        ("/* a *\\\n/", "// c"),
        ("'\"'", 'R"x(")x"'),
        id="c",
    ),
    pytest.param(
        "src/server.ts",
        "const u = 'http://x/*'; const r = /[/*]/; // c\n"
        "const t = `a ${f('`')} b`; if (ok) /x\\/*/.test(u);\n",
        ("// c",),
        ("'http://x/*'", "`a ", "'`'", " b`"),
        id="typescript",
    ),
    pytest.param(
        "scripts/run.sh",
        "#!/bin/sh\necho \"a # b\" $# ${#x} x#y # c\ncat <<'EOF'\n# body\nEOF\n",
        ("# c",),
        (),
        id="shell",
    ),
    pytest.param(
        "Dockerfile",
        "# syntax=docker/dockerfile:1\nFROM alpine\n  # docker.sock prose\n"
        "RUN echo 'a # b' \\\n  # dropped by docker\n  && run # tail\n"
        "RUN <<EOF\n# body\nEOF\nENV X=a#b # an ENV value\n",
        ("# docker.sock prose", "# dropped by docker", "# tail"),
        (),
        id="dockerfile",
    ),
    pytest.param(
        "Cargo.toml",
        "a = \"x # y\" # c\nb = '''\n# kept\n'''\n",
        ("# c",),
        (),
        id="toml",
    ),
    pytest.param(
        "config.yaml",
        "a: it's # c\nb: 'x # y'\nrun: |\n  # body\n",
        ("# c",),
        (),
        id="yaml",
    ),
    pytest.param(
        "Makefile",
        "X = \"a # b\"\nY = $(shell echo '#') # c\nall:\n\techo # recipe\n",
        ('# b"', "# c"),
        (),
        id="make",
    ),
    pytest.param(
        "requirements-dev.txt",
        "pkg==1 # c\npkg @ https://x#egg=pkg\n",
        ("# c",),
        (),
        id="requirements",
    ),
    pytest.param(
        ".env.example",
        "# prose\nKEY=a#b # consumers disagree\n",
        ("# prose",),
        (),
        id="dotenv",
    ),
    pytest.param("setup.cfg", "; c\n# d\nkey = a # e\n", ("; c", "# d"), (), id="ini"),
    pytest.param("README.md", "// x /* y */ # z\n", (), (), id="markdown"),
    pytest.param("web/app.jsx", "// x 'y' /* z\n", (), (), id="jsx"),
    pytest.param("App.java", "// x\n", (), (), id="java"),
]


@pytest.mark.parametrize(("path", "raw", "comments", "strings"), _LANGUAGE_TABLE)
def test_language_table_masks_exactly_the_language_syntax(
    path: str, raw: str, comments: tuple[str, ...], strings: tuple[str, ...]
) -> None:
    comment_masked = mask_comments(raw, path)
    code_only = mask_string_literals(comment_masked, path)

    assert comment_masked == _blank(raw, *comments)
    assert code_only == _blank(comment_masked, *strings)


@pytest.mark.parametrize(
    ("path", "comment"),
    [
        ("src/agent.py", "# {}"),
        ("src/main.rs", "/* {} */"),
        ("cmd/main.go", "// {}"),
        ("csrc/shim.c", "/* {} */"),
        ("src/server.js", "/* {} */"),
        ("scripts/run.sh", "# {}"),
        ("Dockerfile", "# {}"),
        ("Cargo.toml", "# {}"),
        ("config.yml", "# {}"),
        ("Makefile", "# {}"),
        ("requirements.txt", "# {}"),
        (".env", "# {}"),
        ("setup.cfg", "; {}"),
        ("notes.unknown", "// {}"),
    ],
)
def test_masking_preserves_length_and_every_line_boundary(
    path: str, comment: str
) -> None:
    exotic = "a\x0cb\x0bc\x1cd\x85e f g"
    raw = comment.format(exotic) + "\r\nvalue = 1\n" + comment.format("h") + "\n"

    for masked in (
        mask_comments(raw, path),
        mask_string_literals(mask_comments(raw, path), path),
    ):
        assert len(masked) == len(raw)
        assert len(masked.splitlines()) == len(raw.splitlines())
        assert masked.splitlines()[-2] == raw.splitlines()[-2]


def _decisive(path: str, source: str) -> list[dict[str, object]]:
    return find_decisive_malicious_source(
        [(path, source)], explicitly_executable_paths=frozenset({path})
    )


@pytest.mark.parametrize(
    ("path", "source"),
    [
        pytest.param(
            "src/agent.py",
            "# Never read ~/.ssh or .env files here.\nprint('ready')\n",
            id="python-hash-comment",
        ),
        pytest.param(
            "Dockerfile",
            "FROM rust:1\n# Do not mount /var/run/docker.sock; run as a user.\n"
            "RUN cargo build --release\n",
            id="dockerfile-comment",
        ),
        pytest.param(
            "scripts/run.sh",
            "#!/bin/sh\n# We never cat ~/.ssh/id_rsa in this script.\nexec ./server\n",
            id="shell-comment",
        ),
        pytest.param(
            "src/main.rs",
            "fn pick<'a>(x: &'a str) -> &'a str { x }\n"
            'const PROMPT: &str = "don\'t read ~/.ssh/id_rsa ... std::fs::read";\n',
            id="rust-lifetimes-then-prompt",
        ),
    ],
)
def test_prose_never_becomes_a_decisive_finding(path: str, source: str) -> None:
    assert _decisive(path, source) == []


@pytest.mark.parametrize(
    ("path", "source", "category"),
    [
        pytest.param(
            "src/agent.py",
            "import os\nkey = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n",
            "credential_access",
            id="python-credential-read",
        ),
        pytest.param(
            "Dockerfile",
            "FROM alpine\n# prose\n"
            "RUN curl --unix-socket /var/run/docker.sock http://d/containers/json\n",
            "malicious_build",
            id="dockerfile-docker-socket",
        ),
        pytest.param(
            "src/main.rs",
            "fn pick<'a>(x: &'a str) -> &'a str { x }\n"
            'fn leak() { let _ = std::fs::read("/home/miner/.ssh/id_rsa"); }\n',
            "credential_access",
            id="rust-read-after-lifetimes",
        ),
        pytest.param(
            "src/agent.py",
            "import os\n"
            "half = n // 2; key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n",
            "credential_access",
            id="python-floor-division-then-read",
        ),
        pytest.param(
            "scripts/run.sh",
            "#!/bin/sh\ncat ~/.ssh/id_rsa # print the key\n",
            "credential_access",
            id="shell-read-before-comment",
        ),
    ],
)
def test_real_effects_still_fire(path: str, source: str, category: str) -> None:
    assert category in {finding["category"] for finding in _decisive(path, source)}


@pytest.mark.parametrize(
    "literal", ["'x'", "'\"'", "'/'", "'\\n'", "'\\''", "'\\u{1F600}'", "b'\"'"]
)
def test_rust_char_literals_do_not_desynchronize_the_masker(literal: str) -> None:
    source = (
        "fn f<'a, 'b: 'a>(x: &'a str) -> char "
        f"{{ 'outer: loop {{ break {literal}; }} }}"
        ' // "note\n'
        'let url = "https://api.example/v1"; run(); /* c */\n'
    )

    comment_masked = mask_comments(source, "src/main.rs")
    code_only = mask_string_literals(comment_masked, "src/main.rs")

    assert comment_masked == _blank(source, ' // "note', "/* c */")
    assert "run();" in code_only.splitlines()[1]
    assert "https" not in code_only
    assert "'a str" in code_only
    assert "'outer:" in code_only


def test_rust_raw_strings_cannot_close_or_open_comments() -> None:
    source = 'let a = r#"*/"#; run();\nlet b = r##"/* "# "##; go();\n'

    assert mask_comments(source, "src/main.rs") == source
    assert mask_string_literals(source, "src/main.rs") == _blank(
        source, 'r#"*/"#', 'r##"/* "# "##'
    )


def test_block_comment_nesting_follows_the_language() -> None:
    """Rust nests block comments; Go, C, and JavaScript do not.

    Treating a flat-comment language as nesting would let ``/* /* */`` hide
    everything up to a later ``*/``.
    """
    nested = "/* /* */ run(); */\n"
    flat = "/* /* */ run(); /* */\n"

    assert mask_comments(nested, "src/main.rs") == _blank(nested, nested[:-1])
    for path in ("cmd/main.go", "csrc/shim.c", "src/server.js"):
        assert mask_comments(flat, path) == _blank(flat, "/* /* */", "/* */\n")
        assert "run();" in mask_comments(nested, path)


def test_javascript_regex_after_a_condition_is_not_a_comment() -> None:
    source = "if (ready) /[/*]/.test(input);\nrun();\nconst half = total / 2; // c\n"

    assert mask_comments(source, "src/server.js") == _blank(source, "// c")


@pytest.mark.parametrize(
    "source",
    [
        'echo "$(printf " #")" ; cat ~/.ssh/id_rsa\n',
        "echo\\ #; cat ~/.ssh/id_rsa\n",
        "echo a\\\n#b; cat ~/.ssh/id_rsa\n",
        'x=$(case $y in a) echo " #";; esac); cat ~/.ssh/id_rsa\n',
        "echo ${x#*/} ${#y} $# 16#ff; cat ~/.ssh/id_rsa\n",
    ],
)
def test_shell_quoting_and_escapes_cannot_hide_code(source: str) -> None:
    assert mask_comments(source, "scripts/run.sh") == source


@pytest.mark.parametrize(
    ("path", "source"),
    [
        pytest.param("src/main.rs", "/* never closed\nrun();\n", id="rust-comment"),
        pytest.param("src/main.rs", 'let s = "never closed;\nrun();\n', id="rust-str"),
        pytest.param("cmd/main.go", "x := `never closed\nrun() // c\n", id="go-raw"),
        pytest.param("src/app.js", "const a = 'x;\nrun(); // c\n", id="js-string-eol"),
        pytest.param(
            "src/app.js",
            "const el = <p>It's</p>; const u = '/*';\nrun();\n/* */\n",
            id="jsx-in-js",
        ),
        pytest.param("src/app.js", "run(); }\n// c\n", id="js-unbalanced"),
        pytest.param("src/app.js", "x = {a: 1} / 2; // c\n", id="js-regex-eol"),
        pytest.param("src/agent.py", '"""never closed\n# c\nrun()\n', id="python"),
        pytest.param("scripts/run.sh", "echo 'never closed\n# c\n", id="shell"),
        pytest.param("config.yaml", 'a: "never closed\n# c\n', id="yaml"),
    ],
)
def test_sources_that_do_not_lex_are_left_unmasked(path: str, source: str) -> None:
    assert mask_comments(source, path) == source
    assert mask_string_literals(source, path) == source


def test_python_that_does_not_tokenize_still_masks_hash_comments() -> None:
    """Python 2 or mixed indentation falls back to a quote-aware ``#`` lexer."""
    source = "def f():\n\tx = 'a # b'  # c\n        return x // 2\n"

    assert mask_comments(source, "src/legacy.py") == _blank(source, "# c")


@pytest.mark.parametrize(
    ("path", "language"),
    [
        ("src/agent.py", "python"),
        ("stubs/x.pyi", "python"),
        ("src/main.rs", "rust"),
        ("web/server.mjs", "javascript"),
        ("web/app.tsx", None),
        ("docker/Dockerfile.dev", "dockerfile"),
        ("build/app.dockerfile", "dockerfile"),
        ("Containerfile", "dockerfile"),
        ("GNUmakefile", "make"),
        ("rules.mk", "make"),
        ("requirements-dev.txt", "requirements"),
        ("notes.txt", None),
        (".env.local", "dotenv"),
        ("Pipfile", "toml"),
        ("package.json", None),
        ("lib/tool.rb", None),
        ("LICENSE", None),
    ],
)
def test_language_table_is_explicit(path: str, language: str | None) -> None:
    assert language_for_path(path) == language


@pytest.mark.parametrize(
    ("path", "comment"),
    [
        ("src/agent.py", "# prose"),
        ("scripts/run.sh", "# prose"),
        ("src/cli.js", "// prose"),
    ],
)
def test_interpreter_line_stays_visible(path: str, comment: str) -> None:
    """The kernel runs a ``#!`` line; ``env -S`` makes it a whole command."""
    source = f"#!/usr/bin/env -S sh -c 'cat ~/.ssh/id_rsa'\n{comment}\n"

    assert mask_comments(source, path) == _blank(source, comment)


def test_dockerfile_rules_that_change_the_shell_leave_run_text_visible() -> None:
    source = 'SHELL ["cmd", "/S", "/C"]\nRUN echo a # b\n# c\n'

    assert mask_comments(source, "Dockerfile") == _blank(source, "# c")


def test_dockerfile_directive_only_counts_at_the_top() -> None:
    source = "# syntax=example/frontend\nFROM alpine\n# syntax=later\n"

    assert mask_comments(source, "Dockerfile") == _blank(source, "# syntax=later")


def test_dockerfile_exec_form_is_not_shell_lexed() -> None:
    source = 'CMD ["sh", "-c", "run # not a Dockerfile comment"]\n'

    assert mask_comments(source, "Dockerfile") == source


_FUZZ_PIECES = [
    *"ab x=;(){}[]<>/\\*#'\"`$|&-:!?.,01rbfL@",
    *_LINE_BREAKS,
    "\r\n",
    "\t",
    "\u00e9",
    "\ufeff",
    "//",
    "/*",
    "*/",
    "'''",
    '"""',
    "${",
    "$(",
    "<<",
    "<<EOF\n",
    "\nEOF\n",
    'r#"',
    '"#',
    "'a",
    "'x'",
    "RUN ",
    "\\\n",
    "|\n",
    "- ",
    ": ",
    "case ",
    "esac",
    "f'",
    "#!",
    "if (",
    ") /",
    'R"(',
]
_FUZZ_PATHS = [
    "a.rs",
    "a.go",
    "a.c",
    "a.js",
    "a.ts",
    "a.py",
    "a.sh",
    "Dockerfile",
    "a.toml",
    "a.yaml",
    "Makefile",
    "requirements.txt",
    ".env",
    "a.ini",
    "a.md",
]


def test_masking_never_raises_and_only_blanks_on_arbitrary_text() -> None:
    """Untrusted bytes must not crash a scanner or shift its line numbers."""
    rng = random.Random(2457)
    for _ in range(300):
        raw = "".join(rng.choice(_FUZZ_PIECES) for _ in range(rng.randint(0, 60)))
        for path in _FUZZ_PATHS:
            comment_masked = mask_comments(raw, path)
            for masked in (comment_masked, mask_string_literals(comment_masked, path)):
                assert len(masked) == len(raw)
                assert len(masked.splitlines()) == len(raw.splitlines())
                assert all(a == b or b == " " for a, b in zip(raw, masked, strict=True))


@pytest.mark.parametrize(
    ("path", "source"),
    [
        pytest.param("src/app.js", "x = /[ " * 15_000, id="js-unclosed-regex-classes"),
        pytest.param("src/app.js", "a" * 100_000 + " b (1)", id="js-long-identifier"),
        pytest.param("csrc/a.c", "1" + "'1" * 50_000, id="c-digit-separators"),
        pytest.param("csrc/a.c", "a'b'" * 25_000, id="c-char-literal-chain"),
        pytest.param("scripts/run.sh", "\\" * 100_000 + " #x", id="shell-backslashes"),
    ],
)
def test_crafted_sources_lex_in_linear_time(path: str, source: str) -> None:
    """A quadratic lexer would let one submission stall a screener for minutes."""
    started = time.perf_counter()
    mask_string_literals(mask_comments(source, path), path)
    assert time.perf_counter() - started < 5
