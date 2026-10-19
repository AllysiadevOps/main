from __future__ import annotations

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import generate_synthetic_media as generator


class SyntheticMediaGeneratorTest(unittest.TestCase):
    def test_command_is_stable_for_identical_inputs(self) -> None:
        output = Path("fixture.mp4")
        first = generator.build_command("ffmpeg", output, 320, 240, 3, 30, 17)
        second = generator.build_command("ffmpeg", output, 320, 240, 3, 30, 17)
        explicit_none = generator.build_command("ffmpeg", output, 320, 240, 3, 30, 17, "none")
        self.assertEqual(first, second)
        self.assertEqual(first, explicit_none)
        self.assertIn("testsrc2=size=320x240:rate=30,noise=alls=10:all_seed=17", first)
        self.assertIn("creation_time=1970-01-01T00:00:00Z", first)
        self.assertIn("-an", first)
        self.assertNotIn("-c:a", first)

    def test_audio_commands_are_deterministic_and_seeded(self) -> None:
        output = Path("fixture.mp4")
        sine_first = generator.build_command("ffmpeg", output, 320, 240, 3, 30, 17, "sine")
        sine_second = generator.build_command("ffmpeg", output, 320, 240, 3, 30, 17, "sine")
        sine_other_seed = generator.build_command("ffmpeg", output, 320, 240, 3, 30, 42, "sine")
        self.assertEqual(sine_first, sine_second)
        self.assertNotEqual(sine_first, sine_other_seed)
        self.assertNotIn("-an", sine_first)
        self.assertIn("sine=frequency=237:sample_rate=44100", sine_first)
        self.assertIn("-c:a", sine_first)
        self.assertIn("aac", sine_first)
        self.assertIn("-flags:a", sine_first)

        noise_first = generator.build_command("ffmpeg", output, 320, 240, 3, 30, 17, "noise")
        noise_second = generator.build_command("ffmpeg", output, 320, 240, 3, 30, 17, "noise")
        noise_other_seed = generator.build_command("ffmpeg", output, 320, 240, 3, 30, 42, "noise")
        self.assertEqual(noise_first, noise_second)
        self.assertNotEqual(noise_first, noise_other_seed)
        self.assertNotEqual(sine_first, noise_first)
        self.assertNotIn("-an", noise_first)
        self.assertIn("anoisesrc=color=white:sample_rate=44100:amplitude=0.1:seed=17", noise_first)
        self.assertIn("-c:a", noise_first)
        self.assertIn("aac", noise_first)
        self.assertIn("-flags:a", noise_first)

    def test_rejects_unsafe_dimensions_and_seed_bounds(self) -> None:
        with self.assertRaisesRegex(generator.GeneratorError, "width"):
            generator.validate_options(Path("fixture.mp4"), 17, 240, 3, 30, 0)
        with self.assertRaisesRegex(generator.GeneratorError, "seed"):
            generator.validate_options(Path("fixture.mp4"), 320, 240, 3, 30, -1)

    def test_validates_audio_option(self) -> None:
        for mode in ("none", "sine", "noise"):
            generator.validate_options(Path("fixture.mp4"), 320, 240, 3, 30, 0, mode)
        for invalid in ("", "chirp", "pcm", "SINE"):
            with self.assertRaisesRegex(generator.GeneratorError, "audio"):
                generator.validate_options(Path("fixture.mp4"), 320, 240, 3, 30, 0, invalid)
            with self.assertRaisesRegex(generator.GeneratorError, "audio"):
                generator.build_command("ffmpeg", Path("fixture.mp4"), 320, 240, 3, 30, 0, invalid)

    def test_does_not_replace_existing_output_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture.mp4"
            output.write_bytes(b"existing")
            with patch.object(generator.subprocess, "run") as run:
                with self.assertRaisesRegex(generator.GeneratorError, "already exists"):
                    generator.generate(output)
                run.assert_not_called()

    def test_rejects_unsupported_output_extension(self) -> None:
        with self.assertRaisesRegex(generator.GeneratorError, r"\.mp4"):
            generator.validate_options(Path("fixture.mov"), 320, 240, 3, 30, 0)

    def test_main_records_audio_option_in_printed_digest_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture.mp4"
            with patch.object(generator, "generate", return_value=(1024, "a" * 64)) as mocked:
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    rc = generator.main(["--output", str(output)])
                self.assertEqual(rc, 0)
                mocked.assert_called_once_with(
                    output,
                    width=320,
                    height=240,
                    duration=3,
                    fps=30,
                    seed=0,
                    audio="none",
                    force=False,
                )
                self.assertIn(f"1024 bytes sha256={'a' * 64} audio=none", stdout.getvalue())

            with patch.object(generator, "generate", return_value=(1024, "a" * 64)) as mocked:
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    rc = generator.main(["--output", str(output), "--seed", "17", "--audio", "sine"])
                self.assertEqual(rc, 0)
                mocked.assert_called_once_with(
                    output,
                    width=320,
                    height=240,
                    duration=3,
                    fps=30,
                    seed=17,
                    audio="sine",
                    force=False,
                )
                self.assertIn(f"1024 bytes sha256={'a' * 64} audio=sine", stdout.getvalue())

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = generator.main(["--output", str(output), "--audio", "invalid"])
            self.assertEqual(rc, 1)
            self.assertIn("audio", stderr.getvalue())

    @unittest.skipUnless(shutil.which("ffmpeg"), "ffmpeg is required")
    def test_ffmpeg_generates_deterministic_audio_variants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            none_path = root / "none.mp4"
            sine_a = root / "sine-a.mp4"
            sine_b = root / "sine-b.mp4"
            noise_a = root / "noise-a.mp4"
            noise_b = root / "noise-b.mp4"

            _, none_digest = generator.generate(none_path, duration=1, seed=17, audio="none")
            _, sine_digest_a = generator.generate(sine_a, duration=1, seed=17, audio="sine")
            _, sine_digest_b = generator.generate(sine_b, duration=1, seed=17, audio="sine")
            _, noise_digest_a = generator.generate(noise_a, duration=1, seed=17, audio="noise")
            _, noise_digest_b = generator.generate(noise_b, duration=1, seed=17, audio="noise")

            self.assertEqual(sine_digest_a, sine_digest_b)
            self.assertEqual(noise_digest_a, noise_digest_b)
            self.assertNotEqual(none_digest, sine_digest_a)
            self.assertNotEqual(none_digest, noise_digest_a)
            self.assertNotEqual(sine_digest_a, noise_digest_a)


if __name__ == "__main__":
    unittest.main()