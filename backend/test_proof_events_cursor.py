from __future__ import annotations

import base64
import unittest
from unittest.mock import MagicMock, patch

import app as app_module
import db as db_module
from db import (
    PROOF_EVENTS_DEFAULT_LIMIT,
    PROOF_EVENTS_MAX_LIMIT,
    clamp_proof_events_limit,
    decode_proof_events_cursor,
    encode_proof_events_cursor,
    find_proof_events_by_video,
)


def _event(event_id: int) -> dict:
    return {
        "id": event_id,
        "event_type": "register",
        "file_name": f"evidence-{event_id}.mp4",
        "video_hash": "a" * 64,
        "metadata_hash": "b" * 64,
        "proof_id": "c" * 64,
        "tier": "source",
        "embedded_hash": None,
        "tx_hash": None,
        "tx_status": None,
        "source_address": None,
        "contract_id": None,
        "metadata": None,
        "created_at": None,
    }


class ProofEventsCursorHelpersTest(unittest.TestCase):
    def test_encode_decode_roundtrip(self) -> None:
        token = encode_proof_events_cursor(42)
        self.assertNotEqual(token, "42")
        self.assertEqual(decode_proof_events_cursor(token), 42)

    def test_decode_rejects_malformed_cursors(self) -> None:
        for bad in ("", " ", "%%%", "not-base64!", "YQ==", "-1", "0"):
            with self.subTest(cursor=bad):
                with self.assertRaises(ValueError):
                    decode_proof_events_cursor(bad)

        # Valid base64 that is not a positive integer id.
        negative = base64.urlsafe_b64encode(b"-9").decode("ascii")
        with self.assertRaises(ValueError):
            decode_proof_events_cursor(negative)

    def test_limit_clamp(self) -> None:
        self.assertEqual(clamp_proof_events_limit(0), 1)
        self.assertEqual(clamp_proof_events_limit(25), 25)
        self.assertEqual(clamp_proof_events_limit(PROOF_EVENTS_MAX_LIMIT + 50), PROOF_EVENTS_MAX_LIMIT)


class ProofEventsCursorApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = app_module.app.test_client()

    def test_malformed_cursor_returns_400(self) -> None:
        response = self.client.get("/api/proofs?cursor=not-a-valid-cursor")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"], "invalid cursor")

    def test_non_integer_limit_returns_400(self) -> None:
        response = self.client.get("/api/proofs?limit=abc")
        self.assertEqual(response.status_code, 400)
        error = response.json["error"]
        if isinstance(error, dict):
            self.assertEqual(error["message"], "limit must be an integer")
        else:
            self.assertEqual(error, "limit must be an integer")

    def test_first_page_includes_next_cursor(self) -> None:
        events = [_event(10), _event(9)]
        next_cursor = encode_proof_events_cursor(9)
        with patch.object(app_module, "list_proof_events", return_value=(events, next_cursor)) as listed:
            response = self.client.get("/api/proofs?limit=2")

        self.assertEqual(response.status_code, 200)
        body = response.json
        self.assertTrue(body["ok"])
        self.assertEqual([item["id"] for item in body["events"]], [10, 9])
        self.assertEqual(body["nextCursor"], next_cursor)
        listed.assert_called_once_with(2, cursor_id=None)

    def test_follow_up_page_passes_decoded_cursor(self) -> None:
        cursor = encode_proof_events_cursor(9)
        events = [_event(8)]
        with patch.object(app_module, "list_proof_events", return_value=(events, None)) as listed:
            response = self.client.get(f"/api/proofs?limit=2&cursor={cursor}")

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.json["nextCursor"])
        listed.assert_called_once_with(2, cursor_id=9)

    def test_traversal_without_duplicates(self) -> None:
        """Simulate keyset pages over a descending id stream with inserts."""
        # Existing evidence ids (newest first). New inserts get higher ids.
        store = [_event(i) for i in range(10, 0, -1)]

        def fake_list(limit: int, *, cursor_id: int | None = None):
            page_size = clamp_proof_events_limit(limit)
            filtered = [row for row in store if cursor_id is None or row["id"] < cursor_id]
            window = filtered[: page_size + 1]
            next_cursor = None
            if len(window) > page_size:
                window = window[:page_size]
                next_cursor = encode_proof_events_cursor(window[-1]["id"])
            return window, next_cursor

        seen: list[int] = []
        cursor: str | None = None
        with patch.object(app_module, "list_proof_events", side_effect=fake_list):
            # Mid-traversal insert of a newer event must not duplicate prior pages.
            for page_index in range(5):
                if page_index == 1:
                    store.insert(0, _event(11))

                query = "/api/proofs?limit=3"
                if cursor:
                    query = f"{query}&cursor={cursor}"
                response = self.client.get(query)
                self.assertEqual(response.status_code, 200)
                page_ids = [item["id"] for item in response.json["events"]]
                seen.extend(page_ids)
                cursor = response.json["nextCursor"]
                if cursor is None:
                    break

        self.assertEqual(len(seen), len(set(seen)), f"duplicate ids in traversal: {seen}")
        # Pages after the insert continue from the prior cursor and never re-read
        # already returned ids (keyset stability).
        self.assertNotIn(11, seen)

    def test_composite_cursor_boundary_and_duplicate_timestamps(self) -> None:
        """Test cursor traversal when multiple events share identical timestamps."""
        timestamp = "2026-09-24T12:00:00Z"
        video_hash = "a" * 64
        # 5 events with identical created_at timestamp
        events_batch = []
        for i in range(5, 0, -1):
            e = _event(i)
            e["created_at"] = timestamp
            events_batch.append(e)

        def fake_list(limit: int, *, cursor_id: int | None = None):
            page_size = clamp_proof_events_limit(limit)
            filtered = [r for r in events_batch if cursor_id is None or r["id"] < cursor_id]
            window = filtered[: page_size + 1]
            next_cursor = None
            if len(window) > page_size:
                window = window[:page_size]
                next_cursor = encode_proof_events_cursor(window[-1]["id"])
            return window, next_cursor

        def fake_by_video(vh: str, limit: int = PROOF_EVENTS_DEFAULT_LIMIT, *, cursor_id: int | None = None):
            self.assertEqual(vh, video_hash)
            return fake_list(limit, cursor_id=cursor_id)

        with (
            patch.object(app_module, "list_proof_events", side_effect=fake_list),
            patch.object(app_module, "find_proof_events_by_video", side_effect=fake_by_video),
        ):
            for base_url in ("/api/proofs", f"/api/proofs/by-video/{video_hash}"):
                with self.subTest(endpoint=base_url):
                    # Page 1 (limit 2) -> ids 5, 4
                    res1 = self.client.get(f"{base_url}?limit=2")
                    self.assertEqual(res1.status_code, 200)
                    self.assertEqual([item["id"] for item in res1.json["events"]], [5, 4])
                    c1 = res1.json["nextCursor"]
                    self.assertIsNotNone(c1)

                    # Page 2 (limit 2) -> ids 3, 2
                    res2 = self.client.get(f"{base_url}?limit=2&cursor={c1}")
                    self.assertEqual(res2.status_code, 200)
                    self.assertEqual([item["id"] for item in res2.json["events"]], [3, 2])
                    c2 = res2.json["nextCursor"]
                    self.assertIsNotNone(c2)

                    # Page 3 (limit 2) -> id 1
                    res3 = self.client.get(f"{base_url}?limit=2&cursor={c2}")
                    self.assertEqual(res3.status_code, 200)
                    self.assertEqual([item["id"] for item in res3.json["events"]], [1])
                    self.assertIsNone(res3.json["nextCursor"])

    def test_empty_result_page(self) -> None:
        """Test API behavior when no proof events exist."""
        with patch.object(app_module, "list_proof_events", return_value=([], None)):
            response = self.client.get("/api/proofs?limit=25")
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json["ok"])
            self.assertEqual(response.json["events"], [])
            self.assertIsNone(response.json["nextCursor"])

    def test_privacy_no_sensitive_leak_in_error(self) -> None:
        """Assert public error responses do not leak sensitive values or stack traces."""
        response = self.client.get("/api/proofs?cursor=invalid_secret_token_12345")
        self.assertEqual(response.status_code, 400)
        body = response.json
        # Error must be privacy safe
        self.assertEqual(body.get("error"), "invalid cursor")
        raw_text = str(body)
        self.assertNotIn("secret", raw_text)
        self.assertNotIn("witness", raw_text)
        self.assertNotIn("SELECT", raw_text)
        self.assertNotIn("Traceback", raw_text)


class ProofByVideoCursorApiTest(unittest.TestCase):
    VIDEO_HASH = "a" * 64

    def setUp(self) -> None:
        self.client = app_module.app.test_client()

    @staticmethod
    def _mock_db_fetchall(rows: list[dict]):
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = rows
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_get_conn = MagicMock()
        mock_get_conn.return_value.__enter__.return_value = mock_conn
        return mock_get_conn, mock_cursor

    def test_default_limit_applies_when_omitted(self) -> None:
        events = [_event(10), _event(9)]
        with patch.object(app_module, "find_proof_events_by_video", return_value=(events, None)) as finder:
            response = self.client.get(f"/api/proofs/by-video/{self.VIDEO_HASH}")

        self.assertEqual(response.status_code, 200)
        body = response.json
        self.assertTrue(body["ok"])
        self.assertEqual([item["id"] for item in body["events"]], [10, 9])
        self.assertIsNone(body["nextCursor"])
        finder.assert_called_once_with(self.VIDEO_HASH, PROOF_EVENTS_DEFAULT_LIMIT, cursor_id=None)

    def test_first_page_includes_next_cursor(self) -> None:
        events = [_event(10), _event(9)]
        next_cursor = encode_proof_events_cursor(9)
        with patch.object(app_module, "find_proof_events_by_video", return_value=(events, next_cursor)) as finder:
            response = self.client.get(f"/api/proofs/by-video/{self.VIDEO_HASH}?limit=2")

        self.assertEqual(response.status_code, 200)
        body = response.json
        self.assertTrue(body["ok"])
        self.assertEqual([item["id"] for item in body["events"]], [10, 9])
        self.assertEqual(body["nextCursor"], next_cursor)
        finder.assert_called_once_with(self.VIDEO_HASH, 2, cursor_id=None)

    def test_next_page_passes_decoded_cursor(self) -> None:
        cursor = encode_proof_events_cursor(9)
        events = [_event(8), _event(7)]
        with patch.object(app_module, "find_proof_events_by_video", return_value=(events, None)) as finder:
            response = self.client.get(f"/api/proofs/by-video/{self.VIDEO_HASH}?limit=2&cursor={cursor}")

        self.assertEqual(response.status_code, 200)
        body = response.json
        self.assertTrue(body["ok"])
        self.assertEqual([item["id"] for item in body["events"]], [8, 7])
        self.assertIsNone(body["nextCursor"])
        finder.assert_called_once_with(self.VIDEO_HASH, 2, cursor_id=9)

    def test_invalid_cursor_returns_400(self) -> None:
        for bad in ("not-a-valid-cursor", "%%%", "0", "-1", base64.urlsafe_b64encode(b"0").decode("ascii")):
            with self.subTest(cursor=bad):
                response = self.client.get(f"/api/proofs/by-video/{self.VIDEO_HASH}?cursor={bad}")
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json["error"], "invalid cursor")

    def test_non_integer_limit_returns_400(self) -> None:
        response = self.client.get(f"/api/proofs/by-video/{self.VIDEO_HASH}?limit=abc")
        self.assertEqual(response.status_code, 400)
        error = response.json["error"]
        if isinstance(error, dict):
            self.assertEqual(error["message"], "limit must be an integer")
        else:
            self.assertEqual(error, "limit must be an integer")

    def test_db_find_proof_events_by_video_first_and_next_page_queries(self) -> None:
        # First page: 3 rows returned for limit=2 -> trimmed to 2 with next_cursor for id=9
        mock_get_conn, mock_cursor = self._mock_db_fetchall([_event(10), _event(9), _event(8)])
        with (
            patch.object(db_module, "database_url", return_value="postgresql://localhost/test"),
            patch.object(db_module, "get_connection", mock_get_conn),
        ):
            page1, next_cursor = find_proof_events_by_video(self.VIDEO_HASH, 2)

        self.assertEqual([r["id"] for r in page1], [10, 9])
        self.assertEqual(next_cursor, encode_proof_events_cursor(9))
        sql1, params1 = mock_cursor.execute.call_args[0]
        self.assertIn("where video_hash = %s", sql1.lower())
        self.assertNotIn("id < %s", sql1.lower())
        self.assertIn("order by id desc", sql1.lower())
        self.assertEqual(params1, (self.VIDEO_HASH, 3))

        # Next page using decoded cursor_id=9: 2 rows returned for limit=2 -> no next_cursor
        cursor_id = decode_proof_events_cursor(next_cursor)
        mock_get_conn2, mock_cursor2 = self._mock_db_fetchall([_event(8), _event(7)])
        with (
            patch.object(db_module, "database_url", return_value="postgresql://localhost/test"),
            patch.object(db_module, "get_connection", mock_get_conn2),
        ):
            page2, next_cursor2 = find_proof_events_by_video(self.VIDEO_HASH, 2, cursor_id=cursor_id)

        self.assertEqual([r["id"] for r in page2], [8, 7])
        self.assertIsNone(next_cursor2)
        sql2, params2 = mock_cursor2.execute.call_args[0]
        self.assertIn("where video_hash = %s", sql2.lower())
        self.assertIn("and id < %s", sql2.lower())
        self.assertIn("order by id desc", sql2.lower())
        self.assertEqual(params2, (self.VIDEO_HASH, 9, 3))

    def test_db_find_proof_events_by_video_default_limit_and_clamping(self) -> None:
        mock_get_conn, mock_cursor = self._mock_db_fetchall([])
        with (
            patch.object(db_module, "database_url", return_value="postgresql://localhost/test"),
            patch.object(db_module, "get_connection", mock_get_conn),
        ):
            rows, next_cursor = find_proof_events_by_video(self.VIDEO_HASH)
            self.assertEqual(rows, [])
            self.assertIsNone(next_cursor)
            _, params_default = mock_cursor.execute.call_args[0]
            self.assertEqual(params_default, (self.VIDEO_HASH, PROOF_EVENTS_DEFAULT_LIMIT + 1))

            find_proof_events_by_video(self.VIDEO_HASH, PROOF_EVENTS_MAX_LIMIT + 50)
            _, params_clamped = mock_cursor.execute.call_args[0]
            self.assertEqual(params_clamped, (self.VIDEO_HASH, PROOF_EVENTS_MAX_LIMIT + 1))


if __name__ == "__main__":
    unittest.main()
