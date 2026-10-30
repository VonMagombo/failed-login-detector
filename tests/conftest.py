import os
import sys
from datetime import datetime

import pytest

# Make "import config" / "import src.x" work no matter where pytest runs from
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
import src.database as database  # noqa: E402

# Fixed "now" so syslog year inference is deterministic in tests
REFERENCE = datetime(2026, 10, 27, 12, 0, 0)


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A fresh, empty database in a temp dir. Never touches database/security.db."""
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(config, "REPORT_PATH", str(tmp_path / "report.txt"))
    database.reset_database()
    return tmp_path


def make_line(time, message, host="server", pid=1234, prog="sshd"):
    """Builds a classic-syslog sshd line: make_line("Apr 25 10:00:00", "Failed password ...")."""
    return f"{time} {host} {prog}[{pid}]: {message}"
