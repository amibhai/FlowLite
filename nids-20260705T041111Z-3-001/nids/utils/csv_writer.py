import csv
import os
import threading
from collections import deque
from pathlib import Path
from typing import Dict, List

import pandas as pd


_locks: Dict[str, threading.Lock] = {}
_locks_lock = threading.Lock()


def _get_lock(filepath: str) -> threading.Lock:
    with _locks_lock:
        if filepath not in _locks:
            _locks[filepath] = threading.Lock()
        return _locks[filepath]


def append_rows(
    filepath: Path,
    rows: List[Dict],
    fieldnames: List[str],
) -> None:
    if not rows:
        return

    filepath = Path(filepath)
    lock = _get_lock(str(filepath))

    with lock:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(str(filepath) + ".tmp")
        file_exists = filepath.exists()

        existing_rows: List[Dict] = []
        if file_exists:
            try:
                df = pd.read_csv(filepath, on_bad_lines="skip")
                existing_rows = df.to_dict("records")
            except Exception:
                existing_rows = []

        all_rows = existing_rows + rows

        with open(tmp, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=fieldnames, extrasaction="ignore"
            )
            writer.writeheader()
            writer.writerows(all_rows)

        os.replace(str(tmp), str(filepath))


def read_csv(filepath: Path) -> pd.DataFrame:
    filepath = Path(filepath)
    if not filepath.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(filepath, on_bad_lines="skip")
    except Exception:
        return pd.DataFrame()


def tail_rows(filepath: Path, n: int) -> List[Dict]:
    filepath = Path(filepath)
    if not filepath.exists():
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            dq = deque(reader, maxlen=n)
        return list(dq)
    except Exception:
        return []
