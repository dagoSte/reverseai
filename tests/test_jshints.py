import re
import time
import unittest
from unittest.mock import patch

from reverseai.contract import ContractError, MAX_EXCERPT_BYTES
from reverseai.tools import jshints


# These inert bytes are never imported, evaluated, sent or executed as JavaScript.
# The exact matched prefix is part of the lexical catalog, not a syntax claim.
CASES = (
    ("url", "endpoint", b"https://example.invalid/a?b=1", b"https://example.invalid/a?b=1", b"https:/example.invalid"),
    ("ipv4_port", "endpoint", b"192.0.2.1:443", b"192.0.2.1:443", b"256.0.2.1:443"),
    ("eval", "dynamic_code", b"eval (x)", b"eval (", b"reeval(x)"),
    ("new_function", "dynamic_code", b"new Function('x')", b"new Function(", b"newFunction('x')"),
    ("function_constructor", "dynamic_code", b"Function('x')", b"Function(", b"Functionality('x')"),
    ("timer_string", "dynamic_code", b"setTimeout( 'x', 1)", b"setTimeout( '", b"setTimeout(callback, 1)"),
    ("vm_run", "dynamic_code", b"vm.runInNewContext(x)", b"vm.runInNewContext(", b"vm.runOutside(x)"),
    ("dynamic_import", "dynamic_code", b"import( path)", b"import( p", b"import( 'literal')"),
    ("dynamic_require", "dynamic_code", b"require( path)", b"require( p", b"require( \"literal\")"),
    ("child_process", "shell", b"child_process", b"child_process", b"child_processes"),
    ("process_call", "shell", b"execFileSync(x)", b"execFileSync(", b"execFiles(x)"),
    ("fs_mutation", "filesystem", b"fs.promises.writeFile(x)", b"fs.promises.writeFile(", b"fs.readFile(x)"),
    ("process_env", "credential", b"process.env.KEY", b"process.env", b"process.environment"),
    ("fetch", "network", b"fetch(x)", b"fetch(", b"prefetch(x)"),
    ("xml_http_request", "network", b"XMLHttpRequest", b"XMLHttpRequest", b"XMLHttpRequests"),
    ("web_socket", "network", b"WebSocket", b"WebSocket", b"WebSockets"),
    ("http_request", "network", b"https.request(x)", b"https.request(", b"http.requested(x)"),
    ("net_connect", "network", b"net.createConnection(x)", b"net.createConnection(", b"net.connections(x)"),
    ("dgram", "network", b"dgram", b"dgram", b"dgrams"),
    ("aws_access_key", "credential", b"AKIA" + b"A" * 16, b"AKIA" + b"A" * 16, b"AKIA" + b"A" * 15),
    ("private_key", "credential", b"-----BEGIN RSA PRIVATE KEY-----\nexample", b"-----BEGIN RSA PRIVATE KEY-----", b"-----BEGIN RSA PUBLIC KEY-----"),
    ("credential_assignment", "credential", b'''api_key = "example"''', b'''api_key = "example"''', b"api_key = variable"),
    ("jwt", "credential", b"eyJabcde.abcdefgh.ijklmnop", b"eyJabcde.abcdefgh.ijklmnop", b"eyJabcde.abcdefgh"),
    ("atob", "encoding", b"atob(x)", b"atob(", b"atobbed(x)"),
    ("btoa", "encoding", b"btoa(x)", b"btoa(", b"btoas(x)"),
    ("buffer_decode", "encoding", b"Buffer.from('eA==', 'base64')", b"Buffer.from('eA==', 'base64')", b"Buffer.from('eA==', 'utf8')"),
    ("from_char_code", "encoding", b"String.fromCharCode(65)", b"String.fromCharCode(", b"String.fromCodePoint(65)"),
    ("hex_escapes", "encoding", br"\x41" * 8, br"\x41" * 8, br"\x41" * 7),
    ("unicode_escapes", "encoding", br"\u0041" * 8, br"\u0041" * 8, br"\u0041" * 7),
)


def only(data, hint):
    return [row for row in jshints.scan(data) if row[3] == hint]


class JsHintsTests(unittest.TestCase):
    def test_catalog_names_categories_bytes_and_order(self):
        self.assertIsInstance(jshints.PATTERNS, tuple)
        self.assertEqual([(name, category) for name, category, _ in jshints.PATTERNS],
                         [(name, category) for name, category, *_ in CASES])
        self.assertEqual(len({name for name, _, _ in jshints.PATTERNS}), len(CASES))
        self.assertEqual({category for _, category, _ in jshints.PATTERNS}, {
            "endpoint", "dynamic_code", "shell", "filesystem", "network", "credential", "encoding",
        })
        for name, _, pattern in jshints.PATTERNS:
            with self.subTest(name=name):
                self.assertIsInstance(pattern.pattern, bytes)
                self.assertRegex(name, r"^[a-z][a-z0-9_]*$")
                # No unbounded quantifier. All repetitions have fixed maxima.
                self.assertNotRegex(pattern.pattern, rb"(?<!\\)[*+]")
                self.assertNotRegex(pattern.pattern, rb"\{[0-9]+,\}")
                self.assertIsNone(pattern.search(b""))

    def test_every_pattern_has_exact_positive_and_near_miss(self):
        for name, category, positive, matched, near in CASES:
            with self.subTest(name=name):
                prefix = b"\xff\0// "
                self.assertEqual(only(prefix + positive + b" ;\0", name), [
                    (len(prefix), len(matched), category, name),
                ])
                self.assertEqual(only(near, name), [])

    def test_url_schemes_and_delimiters(self):
        for scheme in (b"http", b"https", b"ws", b"wss", b"ftp"):
            text = scheme + b"://example.invalid/a"
            with self.subTest(scheme=scheme):
                self.assertEqual(only(b'"' + text + b'" trailing', "url"), [
                    (1, len(text), "endpoint", "url"),
                ])
        self.assertEqual(only(b"xhttps://example.invalid", "url"), [])
        self.assertEqual(only(b"https://", "url"), [])

    def test_ipv4_and_port_ranges_and_boundaries(self):
        for text in (b"0.0.0.0:0", b"255.255.255.255:65535", b"192.0.2.1:1"):
            with self.subTest(text=text):
                self.assertEqual(only(text, "ipv4_port"), [(0, len(text), "endpoint", "ipv4_port")])
        for text in (b"01.2.3.4:80", b"1.2.3.999:80", b"1.2.3.4:65536", b"1.2.3.4:080",
                     b"x1.2.3.4:80", b"1.2.3.4:80x", b"1.2.3.4.5:80", b"1.2.3.4:800000"):
            with self.subTest(text=text):
                self.assertEqual(only(text, "ipv4_port"), [])

    def test_dynamic_loading_excludes_only_one_closed_plain_literal(self):
        for api, name in ((b"import", "dynamic_import"), (b"require", "dynamic_require")):
            for arg in (b"'path'", b'"path"', b"`path`", b"`multi\nline`", b"`cash$price`", b"''", b"", b" \t"):
                with self.subTest(api=api, arg=arg):
                    self.assertEqual(only(api + b"( " + arg + b")", name), [])
            self.assertEqual(only(api + b"(x)", name), [(0, len(api) + 2, "dynamic_code", name)])
            for arg in (b"'./plugins/' + name", b'"path" + suffix', b"`path${name}`", br"'escaped\x41'",
                        b"'path', options", b"'unclosed", b"'" + b"x" * 1025 + b"'"):
                with self.subTest(api=api, dynamic=arg):
                    self.assertEqual(only(api + b"( " + arg + b")", name), [(0, len(api) + 3, "dynamic_code", name)])
            self.assertEqual(only(api + b"('" + b"x" * 1024 + b"')", name), [])
        for api in (b"setTimeout", b"setInterval"):
            for quote in (b"'", b'"', b"`"):
                text = api + b"(\n" + quote
                self.assertEqual(only(text, "timer_string"), [(0, len(text), "dynamic_code", "timer_string")])

    def test_call_families_and_identifier_boundaries(self):
        groups = (
            ("process_call", (b"exec", b"execSync", b"execFile", b"execFileSync", b"spawn", b"spawnSync", b"fork")),
            ("fs_mutation", tuple(b"fs." + name for name in (
                b"write", b"writeSync", b"writeFile", b"writeFileSync", b"writev", b"appendFile",
                b"unlink", b"unlinkSync", b"rm", b"rmdir", b"rmSync", b"chmod", b"fchmod", b"lchmodSync"))),
            ("http_request", (b"http.request", b"http.get", b"https.request", b"https.get")),
            ("net_connect", (b"net.connect", b"net.createConnection")),
            ("vm_run", (b"vm.runInContext", b"vm.runInNewContext", b"vm.runInThisContext")),
        )
        for name, apis in groups:
            for api in apis:
                with self.subTest(name=name, api=api):
                    self.assertEqual(len(only(api + b"(x)", name)), 1)
                    self.assertEqual(only(b"_" + api + b"(x)", name), [])
                    if name != "vm_run":
                        self.assertEqual(only(api + b"Extra(x)", name), [])

    def test_process_calls_distinguish_bare_and_known_receivers_from_object_methods(self):
        for api in (b"exec", b"execSync", b"execFile", b"execFileSync", b"spawn", b"spawnSync", b"fork"):
            for receiver in (b"", b"child_process.", b"childProcess.", b"cp."):
                token = receiver + api + b"("
                with self.subTest(api=api, receiver=receiver):
                    at = 3 if api == b"exec" else 3 + len(receiver)
                    self.assertEqual(only(b"// " + token + b"x)", "process_call"), [
                        (at, len(token) - (at - 3), "shell", "process_call"),
                    ])
            for receiver in (b"pattern.", b"/a(b)/.", b"other.", b"c."):
                with self.subTest(api=api, excluded=receiver):
                    expected = [] if api == b"exec" else [(len(receiver), len(api) + 1, "shell", "process_call")]
                    self.assertEqual(only(receiver + api + b"(line)", "process_call"), expected)

    def test_process_call_receiver_whitespace_and_identifier_boundaries(self):
        for gap in (b"", b" ", b"\t", b"\n", b"\r", b"\v", b"\f", b" " * 64):
            for receiver in (b"child_process", b"childProcess", b"cp"):
                token = receiver + gap + b"." + gap + b"exec" + gap + b"("
                with self.subTest(receiver=receiver, gap=gap):
                    self.assertEqual(only(token + b"x)", "process_call"), [
                        (0, len(token), "shell", "process_call"),
                    ])
            for receiver in (b"pattern", b"/re/"):
                with self.subTest(excluded=receiver, gap=gap):
                    self.assertEqual(only(receiver + gap + b"." + gap + b"exec(x)", "process_call"), [])
        for prefix in (b"_", b"$", b"a", b"0", b".", b". "):
            for call in (b"exec", b"cp.exec", b"childProcess.exec", b"child_process.exec"):
                with self.subTest(prefix=prefix, call=call):
                    self.assertEqual(only(prefix + call + b"(x)", "process_call"), [])
        self.assertEqual(only(b"exec" + b" " * 65 + b"(x)", "process_call"), [])
        for call in (b"execSync", b"execFile", b"execFileSync", b"spawn", b"spawnSync", b"fork"):
            token = b"unknown . " + call + b" ("
            with self.subTest(process_specific=call):
                self.assertEqual(only(token + b"x)", "process_call"), [
                    (10, len(call) + 2, "shell", "process_call"),
                ])

    def test_new_function_emits_one_hint_and_preserves_plain_constructors(self):
        for gap in (b" ", b"\t", b"\n", b"\r", b"\v", b"\f", b" " * 64):
            token = b"new" + gap + b"Function" + gap + b"("
            with self.subTest(gap=gap):
                self.assertEqual(list(jshints.scan(b"// " + token + b"x)")), [
                    (3, len(token), "dynamic_code", "new_function"),
                ])
        for prefix in (b"", b"renew ", b"newer ", b"xnew ", b"$new ", b"_new "):
            with self.subTest(prefix=prefix):
                self.assertEqual(list(jshints.scan(prefix + b"Function(x)")), [
                    (len(prefix), 9, "dynamic_code", "function_constructor"),
                ])

    def test_constructor_deduplication_keeps_later_and_overlapping_hints(self):
        data = b"Function(x); new Function(x); new\tFunction (x); eval(x)"
        expected = []
        for token, name in ((b"Function(", "function_constructor"), (b"new Function(", "new_function"),
                            (b"new\tFunction (", "new_function"), (b"eval(", "eval")):
            expected.append((data.index(token), len(token), "dynamic_code", name))
        self.assertEqual(list(jshints.scan(data)), expected)

    def test_credentials_have_literal_values_and_exact_id_boundaries(self):
        for key in (b"api_key", b"apiKey", b"API-KEY", b"secret", b"token", b'"token"', b"'secret'"):
            for sep in (b":", b"="):
                text = key + sep + b"'example'"
                with self.subTest(key=key, sep=sep):
                    self.assertEqual(only(text, "credential_assignment"), [(0, len(text), "credential", "credential_assignment")])
        for text in (b"secret == 'example'", b"token === 'example'", b"secret=> 'example'", b"mysecret='x'",
                     b"token=''", b"token='unclosed", b"'secret\"='x'", b"token=`template`"):
            self.assertEqual(only(text, "credential_assignment"), [], text)
        text = b'''secret="escaped\\\"literal"'''
        self.assertEqual(only(text, "credential_assignment"), [(0, len(text), "credential", "credential_assignment")])
        for prefix in (b"AKIA", b"ASIA"):
            text = prefix + b"A" * 16
            self.assertEqual(len(only(text, "aws_access_key")), 1)
            self.assertEqual(only(text + b"A", "aws_access_key"), [])
            self.assertEqual(only(b"x" + text, "aws_access_key"), [])
        for variant in (b"", b"RSA ", b"EC ", b"DSA ", b"OPENSSH ", b"ENCRYPTED "):
            text = b"-----BEGIN " + variant + b"PRIVATE KEY-----"
            self.assertEqual(only(text + b"\n" + b"a" * 8192, "private_key"), [(0, len(text), "credential", "private_key")])

    def test_encoding_forms_are_lexical_and_bounded(self):
        for quote in (b"'", b'"'):
            for encoding in (b"base64", b"hex"):
                text = b"Buffer . from (value, " + quote + encoding + quote + b")"
                self.assertEqual(only(text, "buffer_decode"), [(0, len(text), "encoding", "buffer_decode")])
        for text in (b"Buffer.from(fn(), 'base64')", b"Buffer.from(value, 'BASE64')", b"Buffer.from(value, 'hex')oops"):
            expected = [] if b"oops" not in text else [(0, len(text) - 4, "encoding", "buffer_decode")]
            self.assertEqual(only(text, "buffer_decode"), expected)
        text = b"String.fromCharCode(65)+String.fromCharCode(66)"
        self.assertEqual(only(text, "from_char_code"), [
            (0, 20, "encoding", "from_char_code"), (24, 20, "encoding", "from_char_code"),
        ])

    def test_comments_and_strings_intentionally_match(self):
        for wrapper in (lambda x: b"// " + x + b"\n", lambda x: b"/* " + x + b" */", lambda x: b'"' + x + b'"'):
            data = wrapper(b"eval(x)")
            self.assertEqual(only(data, "eval"), [(data.index(b"eval"), 5, "dynamic_code", "eval")])

    def test_shared_application_and_bundle_match_declared_byte_spans(self):
        from tests.fixtures_js import app_zip, bundle_js
        direct = {
            "url_https": ("endpoint", "url"), "url_http": ("endpoint", "url"), "url_wss": ("endpoint", "url"),
            "eval_call": ("dynamic_code", "eval"), "fetch_call": ("network", "fetch"),
            "exec_call": ("shell", "process_call"), "aws_key_id": ("credential", "aws_access_key"),
            "private_key": ("credential", "private_key"), "atob_call": ("encoding", "atob"),
            "new_function": ("dynamic_code", "new_function"),
        }
        order = {name: i for i, (name, _, _) in enumerate(jshints.PATTERNS)}
        for builder in (app_zip, bundle_js):
            _, layout = builder()
            for file in layout["files"]:
                if file["name"].endswith("package.json"):
                    continue
                expected = []
                marks = layout["marks"].get(file["name"], ())
                for mark in marks:
                    label, at, length = mark["label"], mark["offset"], mark["length"]
                    if label in direct:
                        category, name = direct[label]
                        expected.append((at, length, category, name))
                    if label == "require_child_process":
                        expected.append((at + 9, 13, "shell", "child_process"))
                    elif label in ("websocket", "xhr"):
                        name = "web_socket" if label == "websocket" else "xml_http_request"
                        expected.append((at + 4, length - 5, "network", name))
                    elif label == "buffer_from":
                        encoding = next(m for m in marks if m["label"] == "base64_encoding")
                        expected.append((at, encoding["offset"] + encoding["length"] + 1 - at, "encoding", "buffer_decode"))
                    elif label == "dynamic_import":
                        expected.append((at, length + 1, "dynamic_code", "dynamic_import"))
                expected.sort(key=lambda row: (row[0], order[row[3]]))
                with self.subTest(builder=builder.__name__, file=file["name"]):
                    self.assertEqual(list(jshints.scan(file["data"])), expected)

    def test_different_patterns_overlap_and_results_sort_by_offset(self):
        data = b'''token="https://192.0.2.1:443"; new Function(x); eval(x)'''
        self.assertEqual(list(jshints.scan(data)), [
            (0, 29, "credential", "credential_assignment"),
            (7, 21, "endpoint", "url"), (15, 13, "endpoint", "ipv4_port"),
            (31, 13, "dynamic_code", "new_function"),
            (48, 5, "dynamic_code", "eval"),
        ])
        patterns = (("z_first", "shell", re.compile(b"x")), ("a_second", "network", re.compile(b"xy")))
        with patch.object(jshints, "PATTERNS", patterns):
            self.assertEqual(list(jshints.scan(b"xy xy")), [
                (0, 1, "shell", "z_first"), (0, 2, "network", "a_second"),
                (3, 1, "shell", "z_first"), (3, 2, "network", "a_second"),
            ])

    def test_whitespace_and_first_argument_limits(self):
        for gap in (b" ", b"\t", b"\n", b"\r", b"\v", b"\f"):
            with self.subTest(gap=gap):
                self.assertEqual(only(b"eval" + gap + b"(x)", "eval"), [(0, 6, "dynamic_code", "eval")])
                self.assertEqual(only(b"new" + gap + b"Function(x)", "new_function"), [(0, 13, "dynamic_code", "new_function")])
                self.assertEqual(only(b"require(" + gap + b"'x')", "dynamic_require"), [])
                self.assertEqual(only(b"import(" + gap + b")", "dynamic_import"), [])
        for gap in (b" " * 64, b"\n\t" * 32):
            self.assertEqual(only(b"eval" + gap + b"(x)", "eval"), [(0, 69, "dynamic_code", "eval")])
            self.assertEqual(only(b"require(" + gap + b"'x')", "dynamic_require"), [])
        self.assertEqual(only(b"eval" + b" " * 65 + b"(x)", "eval"), [])
        for length in (1024, 1025):
            data = b"Buffer.from(" + b"x" * length + b",'hex')"
            self.assertEqual(only(data, "buffer_decode"), [(0, len(data), "encoding", "buffer_decode")] if length == 1024 else [])

    def test_long_matches_never_exceed_the_excerpt_and_keep_later_matches(self):
        for data, name, first_length in (
            (b"https://" + b"a" * 20000, "url", 4088),
            (br"\x41" * 3000, "hex_escapes", 4096),
            (br"\u0041" * 2000, "unicode_escapes", 4092),
        ):
            matches = only(data + b" eval(x)", name)
            self.assertEqual(matches[0][1], first_length)
            self.assertTrue(all(0 < length <= MAX_EXCERPT_BYTES for _, length, _, _ in matches))
            self.assertEqual(only(data + b" eval(x)", "eval"), [(len(data) + 1, 5, "dynamic_code", "eval")])

    def test_empty_binary_and_input_limit_refusal(self):
        self.assertEqual(list(jshints.scan(b"")), [])
        self.assertEqual(list(jshints.scan(bytes(range(256)))), [])
        for value in (None, "eval(x)", bytearray(b"eval(x)"), memoryview(b"eval(x)")):
            with self.subTest(kind=type(value).__name__), self.assertRaisesRegex(ContractError, "^JavaScript input exceeds its limit$"):
                list(jshints.scan(value))
        with patch.object(jshints, "MAX_BYTES", 7):
            self.assertEqual(list(jshints.scan(b"eval(x)")), [(0, 5, "dynamic_code", "eval")])
            with self.assertRaises(ContractError):
                list(jshints.scan(b"eval(x) "))

    def test_future_invalid_pattern_spans_fail_closed(self):
        for source in (b"", b"x{4097}"):
            with patch.object(jshints, "PATTERNS", (("invalid", "shell", re.compile(source)),)):
                with self.assertRaisesRegex(ContractError, "^Invalid JavaScript hint span$"):
                    list(jshints.scan(b"x" * 4097))

    def test_streams_do_not_retain_all_occurrences(self):
        import tracemalloc
        data = b"eval(x);" * 100000
        tracemalloc.start()
        try:
            count = sum(1 for _ in jshints.scan(data))
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(count, 100000)
        self.assertLess(peak, 1024 * 1024)

    def test_each_pattern_on_adversarial_eight_mib_is_bounded(self):
        # Each pattern sees failed starts and long suffixes at 1, 2, 4 and 8 MiB.
        # Fixed spans and disjoint escaped-literal alternatives give O(n) work;
        # this timing guard is a regression probe, not a proof about every CPU.
        # A single pattern must finish an 8 MiB case in 5 seconds on the test host.
        stress = {
            "url": b" https://" + b"a" * 4096,
            "ipv4_port": b" 255.255.255.255:65536 ",
            "new_function": b" new " + b" " * 65 + b"Function ",
            "timer_string": b" setTimeout(" + b" " * 65 + b"x ",
            "vm_run": b" vm.runIn" + b"a" * 65 + b" ",
            "dynamic_import": b" import(" + b" " * 64 + b"'" + b"x" * 1024 + b"'" + b" " * 64 + b") ",
            "dynamic_require": b" require(" + b" " * 64 + b"'" + b"x" * 1024 + b"'" + b" " * 64 + b") ",
            "fs_mutation": b" fs.promises.writeFile" + b" " * 64 + b"x ",
            "process_env": b" process " + b" " * 64 + b"x ",
            "credential_assignment": b' token="' + br"\x" * 512 + b"\n",
            "jwt": b" eyJ" + b"a" * 253 + b"." + b"b" * 1024 + b"." + b"c" * 1025 + b" ",
            "buffer_decode": b" Buffer.from(" + b"x" * 1024 + b", 'utf8') ",
            "hex_escapes": br"\x41" * 1024 + br"\x4Z",
            "unicode_escapes": br"\u0041" * 682 + br"\u004Z",
        }
        for name, _, pattern in jshints.PATTERNS:
            positive = next(row[2] for row in CASES if row[0] == name)
            seed = stress.get(name, b" " + positive.split(b"(")[0] + b" " * 65 + b"x ")
            for mib in (1, 2, 4, 8):
                with self.subTest(name=name, mib=mib):
                    size = mib * 1024 * 1024
                    data = (seed * (size // len(seed) + 1))[:size]
                    started = time.perf_counter()
                    sum(1 for _ in pattern.finditer(data))
                    elapsed = time.perf_counter() - started
                    self.assertLess(elapsed, 5.0, f"{name}: {elapsed:.3f}s at {mib} MiB")


if __name__ == "__main__":
    unittest.main()
