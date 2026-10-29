"""stix-xgs-feed: turn STIX threat intel into Sophos Firewall third-party threat feed files.

Unofficial tool. Not a Sophos product and not supported by Sophos.
"""
__version__ = "0.2.0"

from .cli import build_parser, main  # noqa: E402
from .config import ConfigError, Settings, load_config  # noqa: E402
from .convert import (  # noqa: E402
    Allowlist, Options, PatternError, extract_from_pattern, model_limits, normalise, parse_pattern, parse_ts,
    refang, write_atomic,
)
from .runner import FEED_FILES, RunError, run_once  # noqa: E402

__all__ = [
    "__version__", "main", "build_parser", "ConfigError", "Settings", "load_config", "Allowlist", "Options",
    "PatternError", "extract_from_pattern", "model_limits", "normalise", "parse_pattern", "parse_ts", "refang",
    "write_atomic", "FEED_FILES", "RunError", "run_once",
]
