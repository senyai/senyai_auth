from __future__ import annotations
import sys
import logging


def create_logger(name: str) -> logging.Logger:
    name = name.rsplit(".", 1)[-1]
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            # skip %(asctime)s as it is logged by systemd
            fmt="[%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    logger.addHandler(handler)
    logger.propagate = False
    return logger
