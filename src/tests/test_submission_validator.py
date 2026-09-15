"""
Submission Validation Check
Simulates the GitHub Action .github/workflows/validate.yml locally.
"""

import os
import re


def test_required_files_exist():
    required_files = [
        "README.md",
        "submission.yaml",
        "docs/problem-statement.md",
        "docs/solution-overview.md",
        "docs/architecture.md",
        "docs/setup-guide.md",
        "demo/demo-video-link.txt"
    ]
    for file_path in required_files:
        assert os.path.isfile(file_path), f"Missing required submission file: {file_path}"


def test_submission_yaml_completeness():
    with open("submission.yaml", "r", encoding="utf-8") as f:
        content = f.read()

    assert re.search(r'name:\s*"Pretzel"', content)
    assert re.search(r'track:\s*"AI"', content)
    assert re.search(r'title:\s*"ARES', content)
    assert re.search(r'source_code:\s*"src/"', content)


def test_src_directory_not_empty():
    items = [f for f in os.listdir("src") if f not in ["README.md", ".env.example"]]
    assert len(items) >= 5, "src/ contains insufficient source files"


def test_demo_video_link_not_placeholder():
    with open("demo/demo-video-link.txt", "r", encoding="utf-8") as f:
        first_line = f.readline().strip()
    assert "your-demo-video-link-here" not in first_line


def test_readme_placeholders_replaced():
    with open("README.md", "r", encoding="utf-8") as f:
        content = f.read()
    assert "[Your Project Title Here]" not in content
    assert "[Your Team Name]" not in content
