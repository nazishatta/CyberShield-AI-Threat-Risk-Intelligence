"""Configures Loguru for the whole application."""

import sys

from loguru import logger

from src.utils.config import load_config


def setup_logger() -> None:
    cfg = load_config()
    level = cfg["app"].get("log_level", "INFO")
    logger.remove()
    logger.add(sys.stderr, level=level, colorize=True,
               format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | {message}")
