import re
import subprocess
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parent.parent / "src"
_INLINE_IMPORT_RE = re.compile(r"^\t+(?:from |import )", re.MULTILINE)


def _run_ruff(args: list[str]) -> subprocess.CompletedProcess:
	import shutil

	# Try to find ruff in the current environment
	ruff_bin = shutil.which("ruff")
	if not ruff_bin:
		# Fallback to absolute path in the venv
		ruff_bin = "/home/joan/Documents/IA/pure-mls/.venv/bin/ruff"
	return subprocess.run([ruff_bin] + args, capture_output=True, text=True)


def test_ruff_format():
	"""Validates the indentation policy (Sound of Silence) enforcing Tabs."""
	result = _run_ruff(["format", "--check", "src/", "tests/"])
	assert result.returncode == 0, f"Ruff Format failed:\n{result.stdout}\n{result.stderr}"


def test_ruff_check():
	"""Validates code quality, unused imports and typos."""
	result = _run_ruff(["check", "src/", "tests/"])
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
