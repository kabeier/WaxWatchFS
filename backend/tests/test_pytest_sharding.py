from __future__ import annotations

import pytest
from conftest import assign_files_to_shards, shard_settings_from_env


def test_shard_settings_default_to_unsharded() -> None:
    assert shard_settings_from_env({}) is None
    assert shard_settings_from_env({"PYTEST_SHARD_INDEX": "", "PYTEST_SHARD_TOTAL": ""}) is None
    assert shard_settings_from_env({"PYTEST_SHARD_INDEX": "1", "PYTEST_SHARD_TOTAL": "1"}) is None


def test_shard_settings_parse_valid_selection() -> None:
    assert shard_settings_from_env({"PYTEST_SHARD_INDEX": "2", "PYTEST_SHARD_TOTAL": "3"}) == (2, 3)


@pytest.mark.parametrize(
    ("index", "total"),
    [("0", "3"), ("4", "3"), ("1", "0"), ("x", "3"), ("1", ""), ("", "3")],
)
def test_shard_settings_reject_invalid_selection(index: str, total: str) -> None:
    with pytest.raises(pytest.UsageError):
        shard_settings_from_env({"PYTEST_SHARD_INDEX": index, "PYTEST_SHARD_TOTAL": total})


def test_assign_files_to_shards_is_complete_and_balanced() -> None:
    weights = {
        f"tests/test_{name}.py": weight
        for name, weight in zip("abcdefgh", [26, 19, 16, 15, 3, 2, 1, 1], strict=True)
    }
    assignment = assign_files_to_shards(weights, 3)

    assert set(assignment) == set(weights)
    assert set(assignment.values()) == {1, 2, 3}
    loads = {shard: sum(w for path, w in weights.items() if assignment[path] == shard) for shard in (1, 2, 3)}
    assert max(loads.values()) - min(loads.values()) <= max(weights.values())


def test_assign_files_to_shards_is_deterministic_regardless_of_input_order() -> None:
    weights = {"tests/test_b.py": 5, "tests/test_a.py": 5, "tests/test_c.py": 1}
    reordered = dict(reversed(list(weights.items())))

    assert assign_files_to_shards(weights, 2) == assign_files_to_shards(reordered, 2)
    assert assign_files_to_shards(weights, 2) == {
        "tests/test_a.py": 1,
        "tests/test_b.py": 2,
        "tests/test_c.py": 1,
    }
