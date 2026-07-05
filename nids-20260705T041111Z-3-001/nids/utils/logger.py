import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import SimpleNamespace


_FMT  = "%(asctime)s  %(name)-20s  %(levelname)-8s  %(message)s"
_DFMT = "%Y-%m-%d %H:%M:%S"


def get_logger(name: str, cfg: SimpleNamespace) -> logging.Logger:
    log_dir = Path(cfg.paths.logs)
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(_FMT, datefmt=_DFMT)

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    fh = RotatingFileHandler(
        log_dir / f"{name}.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger
