"""CSV sink and atomic write behaviour."""

from __future__ import annotations

import csv
import threading
from pathlib import Path

import pytest

from flowlite.storage import CsvSink, atomic_write_json, read_csv_rows, read_json
from flowlite.storage.csvsink import SchemaMismatch, iter_csv_rows


class TestAppendSemantics:
    def test_appends_rather_than_rewriting(self, tmp_path: Path):
        path = tmp_path / "out.csv"
        with CsvSink(path, ["a", "b"]) as sink:
            sink.write_rows([{"a": 1, "b": 2}])
            first_size = path.stat().st_size
            sink.write_rows([{"a": 3, "b": 4}])
            second_size = path.stat().st_size
        assert second_size > first_size
        rows = read_csv_rows(path)
        assert [r["a"] for r in rows] == ["1", "3"]

    def test_header_written_once(self, tmp_path: Path):
        path = tmp_path / "out.csv"
        with CsvSink(path, ["a"]) as sink:
            for value in range(5):
                sink.write_row({"a": value})
        text = path.read_text(encoding="utf-8")
        assert text.count("a\n") == 1
        assert len(read_csv_rows(path)) == 5

    def test_reopening_continues_the_same_file(self, tmp_path: Path):
        path = tmp_path / "out.csv"
        CsvSink(path, ["a"]).write_row({"a": 1})
        CsvSink(path, ["a"]).write_row({"a": 2})
        assert [r["a"] for r in read_csv_rows(path)] == ["1", "2"]

    def test_missing_and_extra_keys_are_handled(self, tmp_path: Path):
        path = tmp_path / "out.csv"
        with CsvSink(path, ["a", "b"]) as sink:
            sink.write_row({"a": 1})
            sink.write_row({"a": 2, "b": 3, "unexpected": 4})
        rows = read_csv_rows(path)
        assert rows[0] == {"a": "1", "b": ""}
        assert rows[1] == {"a": "2", "b": "3"}

    def test_empty_batch_is_a_no_op(self, tmp_path: Path):
        path = tmp_path / "out.csv"
        sink = CsvSink(path, ["a"])
        assert sink.write_rows([]) == 0
        assert not path.exists()

    def test_duplicate_field_names_are_rejected(self, tmp_path: Path):
        with pytest.raises(ValueError, match="unique"):
            CsvSink(tmp_path / "x.csv", ["a", "a"])


class TestSchemaLocking:
    def test_changed_schema_rotates_instead_of_corrupting(self, tmp_path: Path):
        path = tmp_path / "out.csv"
        CsvSink(path, ["a", "b"]).write_row({"a": 1, "b": 2})
        CsvSink(path, ["a", "b", "c"]).write_row({"a": 3, "b": 4, "c": 5})

        rows = read_csv_rows(path)
        assert rows == [{"a": "3", "b": "4", "c": "5"}]
        rotated = list(tmp_path.glob("out.*.csv"))
        assert len(rotated) == 1
        assert read_csv_rows(rotated[0]) == [{"a": "1", "b": "2"}]

    def test_error_mode_raises(self, tmp_path: Path):
        path = tmp_path / "out.csv"
        CsvSink(path, ["a"]).write_row({"a": 1})
        with pytest.raises(SchemaMismatch):
            CsvSink(path, ["b"], on_schema_change="error").write_row({"b": 2})

    def test_every_file_has_exactly_one_header(self, tmp_path: Path):
        """The bug this prevents: rows of differing width in one file."""
        path = tmp_path / "out.csv"
        CsvSink(path, ["a", "b"]).write_row({"a": 1, "b": 2})
        CsvSink(path, ["a"]).write_row({"a": 3})
        for target in [path, *tmp_path.glob("out.*.csv")]:
            with target.open(encoding="utf-8", newline="") as handle:
                widths = {len(row) for row in csv.reader(handle)}
            assert len(widths) == 1, f"{target} has rows of differing width"


class TestRobustness:
    def test_formula_injection_is_neutralised(self, tmp_path: Path):
        path = tmp_path / "out.csv"
        CsvSink(path, ["x"]).write_row({"x": "=1+1"})
        assert read_csv_rows(path)[0]["x"] == "'=1+1"

    def test_nan_and_infinity_become_empty(self, tmp_path: Path):
        path = tmp_path / "out.csv"
        with CsvSink(path, ["x"]) as sink:
            sink.write_rows([{"x": float("nan")}, {"x": float("inf")}, {"x": 1.5}])
        assert [r["x"] for r in read_csv_rows(path)] == ["", "", "1.5"]

    def test_deleted_file_is_recreated_with_a_header(self, tmp_path: Path):
        path = tmp_path / "out.csv"
        sink = CsvSink(path, ["a"])
        sink.write_row({"a": 1})
        sink.close()
        path.unlink()
        sink.write_row({"a": 2})
        sink.close()
        assert read_csv_rows(path) == [{"a": "2"}]

    def test_size_rotation(self, tmp_path: Path):
        path = tmp_path / "out.csv"
        with CsvSink(path, ["a"], max_bytes=200) as sink:
            for value in range(200):
                sink.write_row({"a": value})
        assert list(tmp_path.glob("out.*.csv"))

    def test_concurrent_writers_do_not_interleave_rows(self, tmp_path: Path):
        path = tmp_path / "out.csv"
        errors = []

        def writer(worker: int) -> None:
            try:
                sink = CsvSink(path, ["worker", "n"])
                for n in range(50):
                    sink.write_row({"worker": worker, "n": n})
                sink.close()
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors
        rows = read_csv_rows(path)
        assert len(rows) == 300
        assert all(set(row) == {"worker", "n"} for row in rows)


class TestReading:
    def test_corrupt_lines_are_skipped_not_fatal(self, tmp_path: Path):
        path = tmp_path / "bad.csv"
        path.write_text("a,b\n1,2\nbroken\n3,4,5\n6,7\n", encoding="utf-8")
        rows = list(iter_csv_rows(path))
        assert rows == [{"a": "1", "b": "2"}, {"a": "6", "b": "7"}]

    def test_absent_and_empty_files(self, tmp_path: Path):
        assert read_csv_rows(tmp_path / "nope.csv") == []
        empty = tmp_path / "empty.csv"
        empty.touch()
        assert read_csv_rows(empty) == []

    def test_limit(self, tmp_path: Path):
        path = tmp_path / "out.csv"
        with CsvSink(path, ["a"]) as sink:
            sink.write_rows([{"a": i} for i in range(10)])
        assert len(read_csv_rows(path, limit=3)) == 3


class TestAtomicJson:
    def test_round_trip(self, tmp_path: Path):
        path = tmp_path / "state" / "s.json"
        atomic_write_json(path, {"a": [1, 2], "b": "x"})
        assert read_json(path) == {"a": [1, 2], "b": "x"}

    def test_corrupt_file_returns_the_default(self, tmp_path: Path):
        path = tmp_path / "s.json"
        path.write_text("{not json", encoding="utf-8")
        assert read_json(path, default={"fallback": True}) == {"fallback": True}

    def test_no_temporary_files_are_left_behind(self, tmp_path: Path):
        atomic_write_json(tmp_path / "s.json", {"a": 1})
        assert [p.name for p in tmp_path.iterdir()] == ["s.json"]
