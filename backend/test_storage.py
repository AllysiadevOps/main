import os
import stat

import pytest


def test_get_storage_dir_creates_private_directory(monkeypatch, tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX only test")

    from backend import storage

    target = tmp_path / "jobs"
    monkeypatch.setenv("HARPOCRATES_STORAGE_DIR", str(target))

    result = storage.get_storage_dir()

    assert result == target
    assert target.is_dir()
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o700, f"unexpected mode: {oct(mode)}"


def test_get_storage_dir_tightens_existing_directory(monkeypatch, tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX only test")

    from backend import storage

    target = tmp_path / "jobs"
    target.mkdir()
    os.chmod(target, 0o755)
    monkeypatch.setenv("HARPOCRATES_STORAGE_DIR", str(target))

    storage.get_storage_dir()

    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o700, f"unexpected mode: {oct(mode)}"
