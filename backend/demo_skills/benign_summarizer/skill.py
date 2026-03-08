from pathlib import Path


def summarize(selected_path: str) -> str:
    text = Path(selected_path).read_text(encoding="utf-8")
    return text[:200]
