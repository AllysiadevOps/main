import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import contract_bindings as cb  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "contract-bindings" / "spec.json"


def render(spec_path: Path):
    """Fake generator: renders a tiny client from the fixture spec."""
    spec = json.loads(spec_path.read_text(encoding="utf-8"))

    def generator(_wasm: Path, out_dir: Path) -> None:
        (out_dir / "src").mkdir(parents=True)
        lines = [
            f"  {fn['name']}({', '.join(fn['args'])}): {fn['returns']}"
            for fn in spec["functions"]
        ]
        (out_dir / "src" / "index.ts").write_text("class Client {\n" + "\n".join(lines) + "\n}\n", encoding="utf-8")
        (out_dir / "package.json").write_text('{"name":"registry-bindings"}\n', encoding="utf-8")

    return generator


class ContractBindingsDriftTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.out = Path(self._tmp.name) / "committed"
        self.wasm = Path(self._tmp.name) / "unused.wasm"

    def test_generate_then_check_is_clean(self):
        gen = render(FIXTURE)
        cb.generate(self.out, self.wasm, gen)
        self.assertEqual(cb.check(self.out, self.wasm, gen), [])

    def test_generation_is_deterministic(self):
        gen = render(FIXTURE)
        cb.generate(self.out, self.wasm, gen)
        first = (self.out / "src" / "index.ts").read_bytes()
        cb.generate(self.out, self.wasm, gen)
        self.assertEqual(first, (self.out / "src" / "index.ts").read_bytes())

    def test_spec_change_is_reported_as_drift(self):
        cb.generate(self.out, self.wasm, render(FIXTURE))
        changed = json.loads(FIXTURE.read_text(encoding="utf-8"))
        changed["functions"][0]["args"].append("extra")
        spec = Path(self._tmp.name) / "changed.json"
        spec.write_text(json.dumps(changed), encoding="utf-8")
        drift = cb.check(self.out, self.wasm, render(spec))
        self.assertEqual(drift, ["content differs: src/index.ts"])

    def test_missing_and_stale_files_are_reported(self):
        gen = render(FIXTURE)
        cb.generate(self.out, self.wasm, gen)
        (self.out / "package.json").unlink()
        (self.out / "old.ts").write_text("x", encoding="utf-8")
        drift = cb.check(self.out, self.wasm, gen)
        self.assertIn("missing from committed bindings: package.json", drift)
        self.assertIn("stale file not in fresh generation: old.ts", drift)

    def test_crlf_and_build_artifacts_are_ignored(self):
        gen = render(FIXTURE)
        cb.generate(self.out, self.wasm, gen)
        index = self.out / "src" / "index.ts"
        index.write_bytes(index.read_bytes().replace(b"\n", b"\r\n"))
        (self.out / "node_modules").mkdir()
        (self.out / "node_modules" / "junk.js").write_text("x", encoding="utf-8")
        self.assertEqual(cb.check(self.out, self.wasm, gen), [])

    def test_missing_wasm_fails_closed(self):
        with self.assertRaises(cb.BindingsError):
            cb.stellar_generator(self.wasm, Path(self._tmp.name) / "o")

    def test_main_check_exit_codes(self):
        # Missing wasm -> non-zero exit, never a silent pass.
        rc = cb.main(["--check", "--wasm", str(self.wasm), "--output", str(self.out)])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
