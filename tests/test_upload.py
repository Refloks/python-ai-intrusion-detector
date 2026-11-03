import pytest

from upload import get_connection_string


def test_missing_connection_string_stops_with_message(monkeypatch):
    # monkeypatch removes the variable only during this test.
    monkeypatch.delenv("AZURE_STORAGE_CONNECTION_STRING", raising=False)
    with pytest.raises(SystemExit, match="AZURE_STORAGE_CONNECTION_STRING"):
        get_connection_string()


def test_connection_string_is_read_from_environment(monkeypatch):
    monkeypatch.setenv("AZURE_STORAGE_CONNECTION_STRING", "test-value")
    assert get_connection_string() == "test-value"
