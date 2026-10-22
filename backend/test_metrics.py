from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_BACKEND_DIR = str(Path(__file__).resolve().parent)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from flask import Flask, Response

import db
import metrics
from metrics import MetricsCollector


class TestJobQueueMetricsAggregate(unittest.TestCase):
    """Unit tests for db.get_job_queue_metrics()."""

    def test_get_job_queue_metrics_skips_when_no_database(self) -> None:
        with patch.object(db, "database_url", return_value=None):
            result = db.get_job_queue_metrics()
            self.assertEqual(result, {"counts": {}, "oldest_queued_seconds": {}})

    def test_get_job_queue_metrics_aggregates_rows_correctly(self) -> None:
        mock_rows = [
            {
                "type": "embed",
                "state": "pending",
                "count": 5,
                "oldest_queued_seconds": 120.5,
            },
            {
                "type": "embed",
                "state": "running",
                "count": 2,
                "oldest_queued_seconds": None,
            },
            {
                "type": "extract",
                "state": "completed",
                "count": 10,
                "oldest_queued_seconds": None,
            },
            {
                "type": "silent_witness",
                "state": "pending",
                "count": 1,
                "oldest_queued_seconds": 45.0,
            },
        ]

        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = mock_rows
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_conn.__enter__.return_value = mock_conn

        with patch.object(db, "database_url", return_value="postgresql://localhost/test"):
            with patch.object(db, "get_connection", return_value=mock_conn):
                result = db.get_job_queue_metrics()

        self.assertEqual(
            result["counts"],
            {
                ("embed", "pending"): 5,
                ("embed", "running"): 2,
                ("extract", "completed"): 10,
                ("silent_witness", "pending"): 1,
            },
        )
        self.assertEqual(result["oldest_queued_seconds"]["embed"], 120.5)
        self.assertEqual(result["oldest_queued_seconds"]["silent_witness"], 45.0)
        self.assertEqual(result["oldest_queued_seconds"]["extract"], 0.0)

    def test_get_job_queue_metrics_handles_tuple_rows(self) -> None:
        mock_rows = [
            ("embed", "pending", 3, 15.2),
            ("embed", "completed", 8, None),
        ]
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = mock_rows
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_conn.__enter__.return_value = mock_conn

        with patch.object(db, "database_url", return_value="postgresql://localhost/test"):
            with patch.object(db, "get_connection", return_value=mock_conn):
                result = db.get_job_queue_metrics()

        self.assertEqual(result["counts"], {("embed", "pending"): 3, ("embed", "completed"): 8})
        self.assertEqual(result["oldest_queued_seconds"], {"embed": 15.2})

    def test_get_job_queue_metrics_handles_db_exception_gracefully(self) -> None:
        with patch.object(db, "database_url", return_value="postgresql://localhost/test"):
            with patch.object(db, "get_connection", side_effect=RuntimeError("connection dropped")):
                result = db.get_job_queue_metrics()
                self.assertEqual(result, {"counts": {}, "oldest_queued_seconds": {}})

    def test_get_job_metrics_alias(self) -> None:
        self.assertIs(db.get_job_metrics, db.get_job_queue_metrics)


class TestMetricsCollectorJobQueue(unittest.TestCase):
    """Unit tests for MetricsCollector job queue metrics exposition."""

    def setUp(self) -> None:
        self.collector = MetricsCollector(job_refresh_interval=10.0)
        self.collector.reset()

    def test_metrics_skips_job_gauges_when_db_returns_empty(self) -> None:
        with patch.object(db, "get_job_queue_metrics", return_value={"counts": {}, "oldest_queued_seconds": {}}):
            rendered = self.collector.generate_prometheus_metrics(force_refresh_jobs=True)
            self.assertNotIn("harpocrates_jobs", rendered)
            self.assertNotIn("harpocrates_job_oldest_queued_seconds", rendered)

    def test_metrics_renders_gauges_from_mocked_db_aggregate(self) -> None:
        mock_data = {
            "counts": {
                ("embed", "pending"): 4,
                ("embed", "running"): 2,
                ("silent_witness", "pending"): 1,
            },
            "oldest_queued_seconds": {
                "embed": 63.5,
                "silent_witness": 12.0,
            },
        }

        with patch.object(db, "get_job_queue_metrics", return_value=mock_data):
            rendered = self.collector.generate_prometheus_metrics(force_refresh_jobs=True)

            self.assertIn("# HELP harpocrates_jobs Number of jobs by type and state.", rendered)
            self.assertIn("# TYPE harpocrates_jobs gauge", rendered)
            self.assertIn('harpocrates_jobs{type="embed",state="pending"} 4', rendered)
            self.assertIn('harpocrates_jobs{type="embed",state="running"} 2', rendered)
            self.assertIn('harpocrates_jobs{type="silent_witness",state="pending"} 1', rendered)

            self.assertIn("# HELP harpocrates_job_oldest_queued_seconds Age of oldest queued job in seconds by type.", rendered)
            self.assertIn("# TYPE harpocrates_job_oldest_queued_seconds gauge", rendered)
            self.assertIn('harpocrates_job_oldest_queued_seconds{type="embed"} 63.5', rendered)
            self.assertIn('harpocrates_job_oldest_queued_seconds{type="silent_witness"} 12', rendered)

    def test_metrics_caching_bounds_query_cost(self) -> None:
        mock_fn = MagicMock(
            return_value={
                "counts": {("embed", "pending"): 1},
                "oldest_queued_seconds": {"embed": 5.0},
            }
        )

        self.collector.set_job_metrics_fn(mock_fn)

        # Call multiple times in rapid succession
        for _ in range(5):
            self.collector.generate_prometheus_metrics()

        # Must only call the fetcher ONCE due to caching
        self.assertEqual(mock_fn.call_count, 1)

        # Force refresh or reset must trigger another fetch
        self.collector.generate_prometheus_metrics(force_refresh_jobs=True)
        self.assertEqual(mock_fn.call_count, 2)

    def test_metrics_no_job_ids_or_payloads_in_labels(self) -> None:
        mock_data = {
            "counts": {
                ("embed", "pending"): 1,
            },
            "oldest_queued_seconds": {
                "embed": 10.0,
            },
        }

        with patch.object(db, "get_job_queue_metrics", return_value=mock_data):
            rendered = self.collector.generate_prometheus_metrics(force_refresh_jobs=True)

            # Ensure no secret or id fields leaked into metric output
            self.assertNotIn("job_id", rendered)
            self.assertNotIn("payload", rendered)
            self.assertNotIn("worker_id", rendered)
            self.assertNotIn("secret", rendered)

    def test_metrics_handles_alternative_return_formats(self) -> None:
        # Test list of dicts format
        list_data = [
            {"type": "embed", "state": "pending", "count": 3, "oldest_queued_seconds": 15.0},
            {"type": "extract", "state": "completed", "count": 7, "oldest_queued_seconds": None},
        ]
        self.collector.set_job_metrics_fn(lambda: list_data)
        rendered = self.collector.generate_prometheus_metrics(force_refresh_jobs=True)

        self.assertIn('harpocrates_jobs{type="embed",state="pending"} 3', rendered)
        self.assertIn('harpocrates_jobs{type="extract",state="completed"} 7', rendered)
        self.assertIn('harpocrates_job_oldest_queued_seconds{type="embed"} 15', rendered)

    def test_metrics_handles_fetch_exception_gracefully(self) -> None:
        def crashing_fetch():
            raise RuntimeError("Database unavailable")

        self.collector.set_job_metrics_fn(crashing_fetch)
        # Must not raise an exception
        rendered = self.collector.generate_prometheus_metrics(force_refresh_jobs=True)
        self.assertIsInstance(rendered, str)
        self.assertNotIn("harpocrates_jobs", rendered)

    def test_record_deleted_blob_metric(self) -> None:
        self.collector.record_deleted_blob(3)
        rendered = self.collector.generate_prometheus_metrics()
        self.assertIn("harpocrates_retention_deleted_blobs_total 3", rendered)



class TestMetricsFlaskEndpoint(unittest.TestCase):
    """Test the /metrics HTTP endpoint integration with job queue gauges."""

    def setUp(self) -> None:
        self.app = Flask(__name__)
        self.collector = MetricsCollector(job_refresh_interval=15.0)
        self.collector.reset()

        @self.app.get("/metrics")
        def metrics_route():
            output = self.collector.generate_prometheus_metrics()
            return Response(output, mimetype="text/plain; version=0.0.4; charset=utf-8")

        self.client = self.app.test_client()

    def test_metrics_endpoint_exposes_job_gauges(self) -> None:
        mock_data = {
            "counts": {
                ("embed", "pending"): 8,
                ("verify_tx", "running"): 3,
            },
            "oldest_queued_seconds": {
                "embed": 99.0,
                "verify_tx": 0.0,
            },
        }

        self.collector.set_job_metrics_fn(lambda: mock_data)
        response = self.client.get("/metrics")

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response.content_type)
        body = response.data.decode("utf-8")

        self.assertIn('harpocrates_jobs{type="embed",state="pending"} 8', body)
        self.assertIn('harpocrates_jobs{type="verify_tx",state="running"} 3', body)
        self.assertIn('harpocrates_job_oldest_queued_seconds{type="embed"} 99', body)
        self.assertIn('harpocrates_job_oldest_queued_seconds{type="verify_tx"} 0', body)


if __name__ == "__main__":
    unittest.main()
