"""The checkpoint is the agent's read registry, so its durability rules matter."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from honeypot_agent.checkpoint import (
    TEMP_SUFFIX,
    Checkpoint,
    load_checkpoint,
    save_checkpoint,
)


def test_a_missing_checkpoint_is_not_an_error(tmp_path: Path) -> None:
    assert load_checkpoint(tmp_path / "absent.json") is None


def test_a_checkpoint_survives_a_save_and_load(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "checkpoint.json"
    save_checkpoint(path, Checkpoint(path="/var/log/cowrie/cowrie.json", offset=4096, inode=77, sequence=3))

    loaded = load_checkpoint(path)

    assert loaded is not None
    assert loaded.offset == 4096
    assert loaded.inode == 77
    assert loaded.sequence == 3
    assert loaded.path == "/var/log/cowrie/cowrie.json"


def test_saving_stamps_the_update_time(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    before = datetime.now(UTC)

    save_checkpoint(path, Checkpoint(path="cowrie.json", offset=1))

    loaded = load_checkpoint(path)
    assert loaded is not None
    assert loaded.updated_at is not None
    stamp = datetime.fromisoformat(loaded.updated_at)
    assert stamp >= before.replace(microsecond=0)
    assert stamp.tzinfo is not None


def test_saving_leaves_no_temporary_file_behind(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"

    save_checkpoint(path, Checkpoint(path="cowrie.json", offset=10))
    save_checkpoint(path, Checkpoint(path="cowrie.json", offset=20))

    assert [p.name for p in tmp_path.iterdir()] == ["checkpoint.json"]
    assert not path.with_name(path.name + TEMP_SUFFIX).exists()


def test_saving_creates_the_parent_directory(tmp_path: Path) -> None:
    path = tmp_path / "a" / "b" / "c" / "checkpoint.json"

    save_checkpoint(path, Checkpoint(path="cowrie.json", offset=1))

    assert path.is_file()


def test_a_corrupted_checkpoint_is_discarded(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    path.write_text("{ this is not json", encoding="utf-8")

    assert load_checkpoint(path) is None


def test_a_checkpoint_that_is_not_an_object_is_discarded(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")

    assert load_checkpoint(path) is None


def test_a_checkpoint_with_wrong_field_types_falls_back_to_defaults(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    path.write_text(
        json.dumps({"path": 42, "offset": "not-a-number", "inode": "x", "sequence": None, "updated_at": 7}),
        encoding="utf-8",
    )

    loaded = load_checkpoint(path)

    assert loaded is not None
    assert loaded.offset == 0
    assert loaded.inode is None
    assert loaded.sequence is None
    assert loaded.updated_at is None


def test_an_unreadable_checkpoint_does_not_raise(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    path.mkdir()  # a directory where a file is expected

    assert load_checkpoint(path) is None


def test_the_timestamp_property_parses_the_stored_value() -> None:
    stamp = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
    checkpoint = Checkpoint(path="c", updated_at=stamp.isoformat())

    assert checkpoint.timestamp == stamp


def test_the_timestamp_property_is_none_without_a_value() -> None:
    assert Checkpoint(path="c").timestamp is None
    assert Checkpoint(path="c", updated_at="not-a-date").timestamp is None


def test_the_written_document_is_readable_json(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"

    save_checkpoint(path, Checkpoint(path="cowrie.json", offset=5, inode=1, sequence=2))

    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["offset"] == 5
    assert stored["path"] == "cowrie.json"


def test_an_offset_past_the_end_of_the_file_is_still_loaded(tmp_path: Path) -> None:
    """The tailer, not the checkpoint, decides whether the offset is usable."""

    path = tmp_path / "checkpoint.json"
    save_checkpoint(path, Checkpoint(path="cowrie.json", offset=10_000, inode=1))

    loaded = load_checkpoint(path)

    assert loaded is not None
    assert loaded.offset == 10_000


def test_saving_twice_keeps_the_newest_value(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"

    save_checkpoint(path, Checkpoint(path="cowrie.json", offset=1, sequence=1))
    save_checkpoint(path, Checkpoint(path="cowrie.json", offset=2, sequence=2))

    loaded = load_checkpoint(path)
    assert loaded is not None
    assert (loaded.offset, loaded.sequence) == (2, 2)


def test_saving_works_on_every_platform(tmp_path: Path) -> None:
    """``_fsync_directory`` cannot open a directory on Windows, so it must no-op.

    The test is the same everywhere: saving simply must not raise, which is the
    behaviour the ``os.name == "nt"`` guard buys.
    """

    from honeypot_agent import checkpoint as module

    save_checkpoint(tmp_path / "checkpoint.json", Checkpoint(path="c", offset=1))

    assert (tmp_path / "checkpoint.json").is_file()
    assert module.TEMP_SUFFIX == ".tmp"
