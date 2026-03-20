import subprocess


def test_ruff_format():
	"""Valida la política de indentación (Sound of Silence) exigiendo Tabs."""
	result = subprocess.run(["uv", "run", "ruff", "format", "--check", "src/", "tests/"], capture_output=True, text=True)
	assert result.returncode == 0, f"Ruff Format falló:\n{result.stdout}\n{result.stderr}"


def test_ruff_check():
	"""Valida la calidad del código, unused imports y typos."""
	result = subprocess.run(["uv", "run", "ruff", "check", "src/", "tests/"], capture_output=True, text=True)
	assert result.returncode == 0, f"Ruff Check falló:\n{result.stdout}\n{result.stderr}"
