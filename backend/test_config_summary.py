import pytest
from config import load_config

# Define the set of fields that are considered secret and should be redacted to a boolean.
SECRET_FIELDS = {
    "metrics_token",
    "tracing_endpoint",
    "register_api_key",
    "register_api_key_previous",
}

def test_redacted_summary_all_fields_classified():
    cfg = load_config()
    summary = cfg.redacted_summary()

    # Ensure every field of AppConfig is present in the summary.
    for field in cfg.__dataclass_fields__:
        assert field in summary, f"Missing field {field} in redacted summary"
        if field in SECRET_FIELDS:
            # Secret fields must be a boolean indicating presence.
            assert isinstance(summary[field], bool), f"Secret field {field} not redacted to bool"
            # The boolean should reflect whether the original value was set.
            original = getattr(cfg, field)
            assert summary[field] == (original is not None), f"Incorrect redaction for {field}"
        else:
            # Non‑secret fields must retain their original value.
            assert summary[field] == getattr(cfg, field), f"Non‑secret field {field} value altered"

    # Ensure no secret value appears in the summary.
    for secret in SECRET_FIELDS:
        val = getattr(cfg, secret)
        if val is not None:
            assert summary[secret] is not val, f"Secret value for {secret} leaked in summary"
