from __future__ import annotations

import pytest

from src.exceptions import ValidationError
from src.utils.helpers import chunk
from src.utils.validators import expand_targets, is_valid_ip


def test_expand_cidr_and_dedup():
    valid, invalid = expand_targets(["192.168.1.0/30", "192.168.1.1"])
    assert valid == ["192.168.1.1", "192.168.1.2"]
    assert invalid == []


def test_invalid_targets_collected():
    valid, invalid = expand_targets(["10.0.0.1", "not-an-ip", ""])
    assert valid == ["10.0.0.1"]
    assert "not-an-ip" in invalid
    assert "" in invalid


def test_empty_targets_rejected():
    with pytest.raises(ValidationError):
        expand_targets([])


def test_expansion_limit_enforced():
    with pytest.raises(ValidationError):
        expand_targets(["10.0.0.0/16"], max_count=100)


def test_is_valid_ip():
    assert is_valid_ip("8.8.8.8")
    assert not is_valid_ip("999.1.1.1")


def test_chunk():
    assert chunk([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]
    with pytest.raises(ValueError):
        chunk([1], 0)
