import re
import subprocess
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parent.parent / "src"
_INLINE_IMPORT_RE = re.compile(r"^\t+(?:from |import )", re.MULTILINE)


def test_ruff_format():
	"""Validates the indentation policy (Sound of Silence) enforcing Tabs."""
	result = subprocess.run(["uv", "run", "ruff", "format", "--check", "src/", "tests/"], capture_output=True, text=True)
	assert result.returncode == 0, f"Ruff Format failed:\n{result.stdout}\n{result.stderr}"


def test_ruff_check():
	"""Validates code quality, unused imports and typos."""
	result = subprocess.run(["uv", "run", "ruff", "check", "src/", "tests/"], capture_output=True, text=True)
	assert result.returncode == 0, f"Ruff Check failed:\n{result.stdout}\n{result.stderr}"


def test_no_inline_imports():
	"""Sound of Silence: all imports in src/ must be at module level (no indented imports)."""
	violations: list[str] = []
	for py_file in sorted(_SRC_DIR.rglob("*.py")):
		text = py_file.read_text()
		for i, line in enumerate(text.splitlines(), 1):
			if _INLINE_IMPORT_RE.match(line):
				rel = py_file.relative_to(_SRC_DIR.parent)
				violations.append(f"  {rel}:{i}: {line.strip()}")
	assert not violations, "Inline imports found in src/ (Sound of Silence violation):\n" + "\n".join(violations)
