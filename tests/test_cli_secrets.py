"""Audit H3: CLI must not leave private key material world-readable."""

import stat
import subprocess
import sys


def test_keygen_priv_file_is_0600(tmp_path) -> None:
	subprocess.run([sys.executable, "-m", "pure_mls.cli", "keygen", "alice"], cwd=tmp_path, check=True)
	priv = tmp_path / "alice.priv"
	assert priv.exists()
	mode = stat.S_IMODE(priv.stat().st_mode)
	assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_create_group_state_is_0600(tmp_path) -> None:
	subprocess.run([sys.executable, "-m", "pure_mls.cli", "keygen", "founder"], cwd=tmp_path, check=True)
	subprocess.run(
		[sys.executable, "-m", "pure_mls.cli", "create-group", "grp", "founder.priv", "--out", "grp.state"],
		cwd=tmp_path,
		check=True,
	)
	state = tmp_path / "grp.state"
	assert state.exists()
	mode = stat.S_IMODE(state.stat().st_mode)
	assert mode == 0o600, f"expected 0600, got {oct(mode)}"
