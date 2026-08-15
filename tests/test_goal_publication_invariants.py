from __future__ import annotations

from pathlib import Path

import pytest

from tools.target_lifecycle import target_lifecycle


def test_target_scoper_script_uses_public_release_layout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "skills" / "target-scoper" / "scripts" / "lint_goal.py"
    script.parent.mkdir(parents=True)
    script.write_text("# public validator\n", encoding="utf-8")
    monkeypatch.setattr(target_lifecycle, "WORKSPACE", tmp_path)

    assert target_lifecycle._target_scoper_script("lint_goal.py") == script


def test_scope_publication_copies_goal_and_appendix_as_one_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = tmp_path / "scopes" / "example"
    goal = scope / "GOAL.md"
    appendix = scope / "EVIDENCE_APPENDIX.md"
    mirror = tmp_path / "targets" / "example" / "GOAL.md"
    scope.mkdir(parents=True)
    goal.write_text(
        "# Goal: Example\n\nGoal schema: 2\n"
        "Evidence appendix: `./EVIDENCE_APPENDIX.md`\n",
        encoding="utf-8",
    )
    appendix.write_text("# Evidence appendix\n", encoding="utf-8")
    monkeypatch.setattr(target_lifecycle, "_validate_goal_source", lambda *_a, **_k: [])

    published_appendix = target_lifecycle._publish_new_target_scope_pair(
        goal,
        appendix,
        mirror,
    )

    assert mirror.read_bytes() == goal.read_bytes()
    assert published_appendix == mirror.parent / "EVIDENCE_APPENDIX.md"
    assert published_appendix.read_bytes() == appendix.read_bytes()


def test_scope_publication_rolls_back_both_files_when_mirror_lint_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = tmp_path / "scopes" / "example"
    goal = scope / "GOAL.md"
    appendix = scope / "EVIDENCE_APPENDIX.md"
    mirror = tmp_path / "targets" / "example" / "GOAL.md"
    scope.mkdir(parents=True)
    goal.write_text("# Goal: Example\n", encoding="utf-8")
    appendix.write_text("# Evidence appendix\n", encoding="utf-8")
    monkeypatch.setattr(
        target_lifecycle,
        "_validate_goal_source",
        lambda *_a, **_k: ["simulated mirror lint failure"],
    )

    with pytest.raises(ValueError, match="simulated mirror lint failure"):
        target_lifecycle._publish_new_target_scope_pair(goal, appendix, mirror)

    assert not mirror.exists()
    assert not (mirror.parent / "EVIDENCE_APPENDIX.md").exists()
