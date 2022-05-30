import json
import os
import socket
from io import StringIO

import penlog
import pytest


def create_logger() -> penlog.Logger:
    buffer = StringIO()
    logger = penlog.Logger("pytest", file_=buffer, flush=True)
    return logger


@pytest.fixture
def logger_json() -> penlog.Logger:
    os.environ["PENLOG_OUTPUT"] = "json"
    return create_logger()


@pytest.fixture
def logger_hr() -> penlog.Logger:
    os.environ["PENLOG_OUTPUT"] = "hr-nano"
    return create_logger()


def test_log_hr(logger_hr: penlog.Logger) -> None:
    logger_hr.log_warning("foo")
    logger_hr.file.seek(0)
    assert logger_hr.file.read() == "foo\n"


def test_log_json(logger_json: penlog.Logger) -> None:
    logger_json.log_warning("foo")
    logger_json.file.seek(0)
    data = logger_json.file.read()
    record = json.loads(data)

    assert record["component"] == "pytest"
    assert record["data"] == "foo"
    assert record["host"] == socket.gethostname()
    assert record["priority"] == penlog.MessagePrio.WARNING
    assert record["type"] == "message"
