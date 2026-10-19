import json
from unittest import mock
import urlib.error

from webhook import (
    sign_payload,
    dispatch_webhook,
    queue_webhook_deliveries,
    get_active_subscriptions,
    validate_event_types,
)


def test_sign_payload():
    payload = b'{"hello": "world"}'
    secret = "mysecret"
    timestamp = 1620000000
    sig = sign_payload(payload, secret, timestamp)
    assert len(sig) == 64  # SHA-256 hex digest length

    sig2 = sign_payload(payload, secret, timestamp)
    assert sig == sig2


@mock.patch("webhook.urllib.request.urlopen")
@mock.patch("webhook.update_delivery_status")
def test_dispatch_webhook_success(mock_update, mock_urlopen):
    mock_response = mock.MagicMock()
    mock_response.getcode.return_value = 200
    mock_urlopen.return_value.__enter__.return_value = mock_response

    delivery = {
        "delivery_id": 1,
        "url": "http://example.com/webhook",
        "secret_key": "sec",
        "retry_count": 0,
        "payload": {"event_type": "embed"}
    }
    dispatch_webhook(delivery)

    mock_update.assert_called_once_with(1, True, 200, 0)


@mock.patch("webhook.urllib.request.urlopen")
@mock.patch("webhook.update_delivery_status")
def test_dispatch_webhook_failure(mock_update, mock_urlopen):
    mock_urlopen.side_effect = urllib.error.HTTPError("http://example.com", 500, "Internal Error", {}, None)

    delivery = {
        "delivery_id": 2,
        "url": "http://example.com/webhook",
        "secret_key": "sec",
        "retry_count": 1,
        "payload": {"event_type": "extract"}
    }
    dispatch_webhook(delivery)

    mock_update.assert_called_once_with(2, False, 500, 1)


def __make_conn(mock_conn, rows):
    cur = mock_conn.cursor().__enter__.return_value
    cur.fetchall.return_value = rows
    return cur


@mock.patch("webhook.mock_get_connection", create=True)
def test_queue_deliveries_filtered(mock_get_conn):
    mock_conn = mock_get_conn.return_value
    cur = __make_conn(mock_conn, [
        (1, "http://example.com/revocations", "sec1", ["revocation"]),
        (2, "http://example.com/embeds", "sec2", ["embed"]),
    ])

    queue_webhook_deliveries(
        event_type="revocation",
        payload={"event_type": "revocation", "id": 7},
    )

    inserted_subs = [call.args[1] for call in cur.execute.call_list if "insert" in call.args[0].lower()]
    assert len(inserted_subs) == 1
    assert inserted_subs[0] == 1


@mock.patch("webhook.mock_get_connection", create=True)
def test_queue_deliveries_unfiltered(mock_get_conn):
    mock_conn = mock_get_conn.return_value
    cur = __make_conn(mock_conn, [
        (1, "http://example.com/all", "sec1", None),
        (2, "http://example.com/embeds", "sec2", ["embed"]),
    ])

    queue_webhook_deliveries(
        event_type="revocation",
        payload={"event_type": "revocation", "id": 8},
    )

    inserted_subs = [call.args[1] for call in cur.execute.call_list if "insert" in call.args[0].lower()]
    assert inserted_subs == [1]


@mock.patch("webhook.mock_get_connection", create=True)
def test_queue_deliveries_unknown_type(mock_get_conn):
    mock_conn = mock_get_conn.return_value
    cur = __make_conn(mock_conn, [])

    queue_webhook_deliveries(
        event_type="not_a_real_event",
        payload={"event_type": "not_a_real_event"},
    )

    inserted_subs = [call.args[1] for call in cur.execute.call_list if "insert" in call.args[0].lower()]
    assert inserted_subs == []


def test_validate_event_types_allows_known():
    assert validate_event_types(["revocation", "embed"]) == ["revocation", "embed"]
    assert validate_event_types(None) == None


def test_validate_event_types_rejects_unknown():
    import pytest

    with pytest.raises(ValueError):
        validate_event_types(["not_a_real_event"])
