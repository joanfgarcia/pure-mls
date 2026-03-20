import subprocess


def test_ruff_format():
	"""Validates the indentation policy (Sound of Silence) enforcing Tabs."""
	result = subprocess.run(["uv", "run", "ruff", "format", "--check", "src/", "tests/"], capture_output=True, text=True)
	assert result.returncode == 0, f"Ruff Format failed:\n{result.stdout}\n{result.stderr}"


def test_ruff_check():
	"""Validates code quality, unused imports and typos."""
	result = subprocess.run(["uv", "run", "ruff", "check", "src/", "tests/"], capture_output=True, text=True)
	assert result.returncode == 0, f"Ruff Check failed:\n{result.stdout}\n{result.stderr}"
