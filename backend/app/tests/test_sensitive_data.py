from __future__ import annotations

from app.sensitive_data import match_sensitive_path
from app.skill_scanner import scan_skill_directory


def test_sensitive_path_matching_avoids_broad_substring_false_positives() -> None:
    assert match_sensitive_path("/tmp/browserify-notes.txt") == []
    assert match_sensitive_path("/tmp/tokens-report.txt") == []
    assert match_sensitive_path("/tmp/dev.envrc") == []
    assert match_sensitive_path("~/.aws/credentials") == ["AWS credentials"]


def test_scanner_does_not_flag_generic_browser_or_token_words(tmp_path) -> None:
    skill_dir = tmp_path / "benign"
    skill_dir.mkdir()
    (skill_dir / "skill.py").write_text(
        "def summarize(browserify_notes, token_count):\n"
        "    return f'{browserify_notes}:{token_count}'\n",
        encoding="utf-8",
    )

    result = scan_skill_directory(skill_dir, scan_id="scan-test")

    assert result.recommendation == "allow"
    assert result.findings == []
