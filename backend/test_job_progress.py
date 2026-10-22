"""Job progress reporting for long media and proof jobs (issue #803).

Covers the throttled progress store in ``db``, the processors that report it
(with mocked media/proof back ends), the ``GET /api/jobs/<id>`` response shape,
and the per-frame callback in ``stego.embed_metadata``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import db
import stego
import worker


class _JobsIsolation(unittest.TestCase):
    """Run each test against an empty in-memory job table."""

    def setUp(self) -> None:
        self._saved_jobs = dict(db._JOBS)
        db._JOBS.clear()

    def tearDown(self) -> None:
        db._JOBS.clear()
        db._JOBS.update(self._saved_jobs)

    def _running_job(self, job_type: str = "embed", payload: dict | None = None) -> int:
        job_id = db.enqueue_job(job_type, payload or {})
        db._JOBS[job_id]["status"] = "running"
        return job_id


class ProgressStoreTests(_JobsIsolation):
    def test_new_job_has_null_progress(self) -> None:
        job_id = db.enqueue_job("embed", {})
        self.assertIn("progress", db.get_job(job_id))
        self.assertIsNone(db.get_job(job_id)["progress"])

    def test_updates_are_throttled_to_one_per_second(self) -> None:
        job_id = self._running_job()
        self.assertTrue(db.report_job_progress(job_id, "embedding", 10, now=100.0))
        self.assertFalse(db.report_job_progress(job_id, "embedding", 20, now=100.5))
        self.assertEqual(db.get_job(job_id)["progress"], {"phase": "embedding", "percent": 10.0})
        self.assertFalse(db.report_job_progress(job_id, "embedding", 30, now=100.999))
        self.assertTrue(db.report_job_progress(job_id, "embedding", 40, now=101.0))
        self.assertEqual(db.get_job(job_id)["progress"], {"phase": "embedding", "percent": 40.0})

    def test_only_running_jobs_accept_progress(self) -> None:
        pending = db.enqueue_job("embed", {})
        self.assertFalse(db.report_job_progress(pending, "embedding", 5, now=1.0))
        self.assertIsNone(db.get_job(pending)["progress"])
        self.assertFalse(db.report_job_progress(999_999, "embedding", 5, now=1.0))

    def test_percent_is_clamped_rounded_or_null(self) -> None:
        job_id = self._running_job()
        db.report_job_progress(job_id, "embedding", 150, now=1.0)
        self.assertEqual(db.get_job(job_id)["progress"]["percent"], 100.0)
        db.report_job_progress(job_id, "embedding", -3, now=2.0)
        self.assertEqual(db.get_job(job_id)["progress"]["percent"], 0.0)
        db.report_job_progress(job_id, "embedding", 33.333, now=3.0)
        self.assertEqual(db.get_job(job_id)["progress"]["percent"], 33.3)
        db.report_job_progress(job_id, "generating_proof", None, now=4.0)
        self.assertEqual(db.get_job(job_id)["progress"], {"phase": "generating_proof", "percent": None})

    def test_invalid_progress_is_rejected(self) -> None:
        job_id = self._running_job()
        for phase in ("", "   ", None, 7):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                db.report_job_progress(job_id, phase, 1, now=1.0)  # type: ignore[arg-type]
        for percent in ("lots", float("nan")):
            with self.subTest(percent=percent), self.assertRaises(ValueError):
                db.report_job_progress(job_id, "embedding", percent, now=1.0)  # type: ignore[arg-type]
        self.assertIsNone(db.get_job(job_id)["progress"])

    def test_long_phase_names_are_truncated(self) -> None:
        job_id = self._running_job()
        db.report_job_progress(job_id, "x" * 500, None, now=1.0)
        self.assertEqual(len(db.get_job(job_id)["progress"]["phase"]), db.JOB_PROGRESS_PHASE_MAX_LENGTH)

    def test_heartbeat_does_not_overwrite_progress(self) -> None:
        job_id = self._running_job()
        db.report_job_progress(job_id, "embedding", 42, now=1.0)
        db.heartbeat_job(job_id, progress=0.5, lease_duration=300)
        self.assertEqual(db.get_job(job_id)["progress"], {"phase": "embedding", "percent": 42.0})
        self.assertIn("heartbeat_at", db.get_job(job_id))


class _FakeClock:
    def __init__(self, step: float) -> None:
        self.now = 0.0
        self.step = step

    def __call__(self) -> float:
        value = self.now
        self.now += self.step
        return value


class ProcessorProgressTests(_JobsIsolation):
    def _record_progress(self):
        calls: list[tuple] = []
        stored: list[tuple] = []

        def recorder(job_id, phase, percent=None, **kwargs):
            calls.append((phase, percent))
            ok = db.report_job_progress(job_id, phase, percent, **kwargs)
            if ok:
                job = db.get_job(job_id)
                stored.append((job["_progress_at"], dict(job["progress"])))
            return ok

        return calls, stored, recorder

    def test_embed_reports_phases_and_frame_percent_at_most_once_per_second(self) -> None:
        job_id = self._running_job("embed", {"metadata": {"proofId": "aa" * 32}, "filename": "clip.mp4"})
        calls, stored, recorder = self._record_progress()

        def fake_embed(source, output, metadata, progress_callback=None):
            for frame in range(1, 11):
                progress_callback(frame, 10)

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "in.mp4"
            source.write_bytes(b"video")
            with patch.object(worker, "get_job_input_path", return_value=source), \
                 patch.object(worker, "get_job_output_path", return_value=Path(tmp) / "out.mp4"), \
                 patch.object(worker, "sha256_file", return_value="ab" * 32), \
                 patch.object(worker, "embed_metadata", side_effect=fake_embed), \
                 patch.object(worker, "insert_proof_event", return_value=1), \
                 patch.object(worker, "report_job_progress", side_effect=recorder), \
                 patch.object(db.time, "monotonic", _FakeClock(0.4)):
                worker.process_embed(db.get_job(job_id))

        phases = [phase for phase, _ in calls]
        self.assertEqual(phases[0], "hashing_source")
        self.assertEqual(phases[1:11], ["embedding"] * 10)
        self.assertEqual(phases[11:], ["hashing_output", "recording"])
        self.assertEqual([p for _, p in calls[1:11]], [float(f * 10) for f in range(1, 11)])
        # Throttle: stored updates are at least one second apart.
        times = [t for t, _ in stored]
        self.assertTrue(all(b - a >= db.JOB_PROGRESS_MIN_INTERVAL_SECONDS for a, b in zip(times, times[1:])))
        self.assertLess(len(stored), len(calls))
        embedding = [p for _, p in stored if p["phase"] == "embedding"]
        self.assertTrue(embedding)
        self.assertTrue(all(0.0 <= p["percent"] <= 100.0 for p in embedding))

    def test_embed_without_frame_count_reports_null_percent(self) -> None:
        job_id = self._running_job("embed", {"metadata": {}, "filename": "clip.mp4"})
        calls, _stored, recorder = self._record_progress()

        def fake_embed(source, output, metadata, progress_callback=None):
            progress_callback(1, None)

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "in.mp4"
            source.write_bytes(b"video")
            with patch.object(worker, "get_job_input_path", return_value=source), \
                 patch.object(worker, "get_job_output_path", return_value=Path(tmp) / "out.mp4"), \
                 patch.object(worker, "sha256_file", return_value="ab" * 32), \
                 patch.object(worker, "embed_metadata", side_effect=fake_embed), \
                 patch.object(worker, "insert_proof_event", return_value=1), \
                 patch.object(worker, "report_job_progress", side_effect=recorder):
                worker.process_embed(db.get_job(job_id))
        self.assertIn(("embedding", None), calls)

    def test_silent_witness_reports_phase_name_before_proof_generation(self) -> None:
        job_id = self._running_job(
            "silent_witness",
            {"video_hash": "aa" * 32, "credential_secret": "CRED-SECRET", "nullifier_secret": "NULL-SECRET"},
        )
        seen: dict = {}

        def fake_generate(video_hash, credential_secret, nullifier_secret):
            seen["progress"] = dict(db.get_job(job_id)["progress"])
            return {"proof": "00"}

        with patch.object(worker, "generate_silent_witness", side_effect=fake_generate):
            result = worker.process_silent_witness(db.get_job(job_id))
        self.assertEqual(result, {"proof": {"proof": "00"}})
        self.assertEqual(seen["progress"], {"phase": "generating_proof", "percent": None})


class JobStatusResponseTests(_JobsIsolation):
    def setUp(self) -> None:
        super().setUp()
        import app as app_module

        self.app = app_module.create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_missing_progress_is_null(self) -> None:
        job_id = db.enqueue_job("embed", {"filename": "clip.mp4", "metadata": {}})
        response = self.client.get(f"/api/jobs/{job_id}")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertIs(body["ok"], True)
        self.assertIsNone(body["job"]["progress"])

    def test_legacy_float_progress_is_reported_as_null(self) -> None:
        job_id = self._running_job()
        db._JOBS[job_id]["progress"] = 0.5  # shape written by older heartbeats
        body = self.client.get(f"/api/jobs/{job_id}").get_json()
        self.assertIsNone(body["job"]["progress"])

    def test_progress_is_reported_without_payload_or_internal_fields(self) -> None:
        job_id = self._running_job(
            "silent_witness",
            {"video_hash": "aa" * 32, "credential_secret": "CRED-SECRET", "nullifier_secret": "NULL-SECRET"},
        )
        db.report_job_progress(job_id, "generating_proof", now=10.0)
        response = self.client.get(f"/api/jobs/{job_id}")
        raw = response.get_data(as_text=True)
        job = json.loads(raw)["job"]
        self.assertEqual(job["progress"], {"phase": "generating_proof", "percent": None})
        self.assertEqual(job["id"], job_id)
        self.assertEqual(job["type"], "silent_witness")
        self.assertEqual(job["status"], "running")
        self.assertNotIn("payload", job)
        self.assertFalse([key for key in job if key.startswith("_")])
        for secret in ("CRED-SECRET", "NULL-SECRET", "credential_secret", "nullifier_secret"):
            self.assertNotIn(secret, raw)

    def test_documented_response_fields(self) -> None:
        job_id = self._running_job()
        db.report_job_progress(job_id, "embedding", 12.5, now=1.0)
        job = self.client.get(f"/api/jobs/{job_id}").get_json()["job"]
        for field in ("id", "type", "status", "result", "progress", "created_at"):
            self.assertIn(field, job)
        self.assertEqual(set(job["progress"]), {"phase", "percent"})

    def test_unknown_job_still_404(self) -> None:
        self.assertEqual(self.client.get("/api/jobs/987654321").status_code, 404)


def _metadata(source: Path) -> dict:
    return {
        "protocol": "harpocrates",
        "version": 1,
        "tier": "silent",
        "sourceHash": stego.sha256_file(source),
        "proofId": "11" * 32,
        "timestamp": "2026-06-18T00:00:00.000Z",
        "fileName": "source.mp4",
    }


class EmbedFrameCallbackTests(unittest.TestCase):
    def test_callback_receives_every_frame_and_the_total(self) -> None:
        if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
            self.skipTest("ffmpeg and ffprobe are required")
        with tempfile.TemporaryDirectory(prefix="harpocrates-progress-test-") as tmp:
            source = Path(tmp) / "source.mp4"
            subprocess.run(
                ["ffmpeg", "-y", "-v", "error", "-f", "lavfi", "-i", "testsrc=size=160x120:rate=10",
                 "-t", "1", "-pix_fmt", "yuv420p", str(source)],
                check=True,
            )
            seen: list[tuple[int, int | None]] = []
            stego.embed_metadata(source, Path(tmp) / "out.mp4", _metadata(source),
                                 progress_callback=lambda done, total: seen.append((done, total)))
        self.assertTrue(seen)
        self.assertEqual([done for done, _ in seen], list(range(1, len(seen) + 1)))
        totals = {total for _, total in seen}
        self.assertEqual(len(totals), 1)
        total = totals.pop()
        if total is not None:
            self.assertEqual(total, len(seen))

    def test_embed_without_callback_still_works(self) -> None:
        if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
            self.skipTest("ffmpeg and ffprobe are required")
        with tempfile.TemporaryDirectory(prefix="harpocrates-progress-test-") as tmp:
            source = Path(tmp) / "source.mp4"
            subprocess.run(
                ["ffmpeg", "-y", "-v", "error", "-f", "lavfi", "-i", "testsrc=size=160x120:rate=10",
                 "-t", "1", "-pix_fmt", "yuv420p", str(source)],
                check=True,
            )
            out = Path(tmp) / "out.mp4"
            stego.embed_metadata(source, out, _metadata(source))
            self.assertTrue(out.exists())


if __name__ == "__main__":
    unittest.main()
