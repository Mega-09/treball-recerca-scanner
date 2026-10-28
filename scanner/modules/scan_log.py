"""
Shared logging + progress helper for the scanner.

Terminal layout per phase:

    === SQL injection ===
    Found: 3 (SQL Injection x2, Missing security header x1)     <- counter, fixed line, only the number/summary changes
    … testing URL param 'category' — boolean-based             <- live line, overwrites itself

Only the counter and the live line move; the counter never scrolls, its
content just updates in place, and the live line below it refreshes.
Individual findings are NOT printed to the terminal — they go to scan.log
in full, one line each, timestamped. scan.log is the complete record for
the report annex.
"""

import logging
import sys
import time
from collections import Counter

# --- File logger: full detail ------------------------------------------------
logger = logging.getLogger("scanner")
logger.setLevel(logging.DEBUG)
_file_handler = logging.FileHandler("scan.log", mode="w", encoding="utf-8")
_file_handler.setFormatter(
    logging.Formatter("%(asctime)s  %(message)s", datefmt="%H:%M:%S")
)
logger.addHandler(_file_handler)
logger.propagate = False

# Optional listeners (e.g. the web UI) that receive every progress message.
_sinks = []

def add_sink(fn):
    """Register a callback(kind, text) called on every log event."""
    _sinks.append(fn)

def clear_sinks():
    _sinks.clear()

def _emit(kind, text):
    for fn in list(_sinks):
        try:
            fn(kind, text)
        except Exception:
            pass

# Does the terminal understand ANSI cursor moves? (Windows Terminal / modern
# PowerShell: yes. Old cmd.exe: often not.) We degrade gracefully if not.
_ANSI = sys.stdout.isatty()

_counter = Counter()          # finding type -> count
_counter_active = False       # is a counter block currently on screen?
_live_len = 0                 # length of the current live line


def _summary():
    total = sum(_counter.values())
    if not total:
        return "Found: 0"
    parts = ", ".join(f"{name} x{n}" for name, n in _counter.items())
    return f"Found: {total} ({parts})"


def title(msg):
    """Permanent section heading. Starts a fresh counter block."""
    global _counter, _counter_active, _live_len
    _end_live()
    _counter = Counter()
    _counter_active = False
    _live_len = 0
    print(f"\n=== {msg} ===")
    logger.info(f"=== {msg} ===")
    _emit("title", msg)
    # print the counter line + an empty live line, then park cursor on live line
    print(_summary())
    print("", end="")
    sys.stdout.flush()
    _counter_active = True


def info(msg):
    """Permanent normal line (breaks out of the counter block)."""
    global _counter_active, _live_len
    _end_live()
    _counter_active = False
    _live_len = 0
    print(f"  {msg}")
    logger.info(msg)
    _emit("info", msg)


def add_finding(finding_type, detail):
    """
    Record a finding: bump the on-screen counter (in place) and write the
    full detail to the log only.
    """
    logger.info(f"[FINDING] {detail}")
    _counter[finding_type] += 1
    _refresh_counter()
    _emit("finding", f"{finding_type}: {detail}")


def transient(msg):
    """Live line under the counter; overwrites itself. Full text to log."""
    global _live_len
    logger.debug(msg)
    line = f"  … {msg}"
    pad = max(0, _live_len - len(line))
    sys.stdout.write("\r" + line + (" " * pad))
    sys.stdout.flush()
    _live_len = len(line)
    _emit("transient", msg)


def _refresh_counter():
    """Rewrite the counter line above the live line, then return to live line."""
    if not _counter_active:
        return
    if _ANSI:
        # move up one line, clear it, write summary, come back down
        sys.stdout.write("\r\033[1A\033[2K" + _summary() + "\n")
        # rewrite the live line we just dropped back onto
        sys.stdout.write("\r" + (" " * _live_len))
        sys.stdout.write("\r")
        sys.stdout.flush()
    # if no ANSI: counter simply isn't live-updated on screen (still in log)


def _end_live():
    global _live_len
    if _live_len:
        sys.stdout.write("\r" + (" " * _live_len) + "\r")
        sys.stdout.flush()
        _live_len = 0
    else:
        # ensure we're on a clean line after the parked live line
        sys.stdout.write("\n")
        sys.stdout.flush()


class Timer:
    def __enter__(self):
        self._start = time.time()
        self.elapsed = 0.0
        return self

    def __exit__(self, *exc):
        self.elapsed = time.time() - self._start