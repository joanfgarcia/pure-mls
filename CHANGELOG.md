# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha] - 2026-03-18
### Added
- Genesis: Repository initialized.
- Added GPLv3 LICENSE.
- Bootstrapped README.md and infrastructure core plan.
- Implemented `protocol_of_silence` as default AI collaboration methodology.
- **Milestone 1**: HKDF standard derivation (`hkdf.py`), Ed25519/X25519 node identity wrappers (`keys.py`), and RFC 9180 HPKE base mode encapsulation (`hpke.py`).
- **Milestone 2**: Left-Balanced Binary Tree (`LBBT`) recursive math for TreeKEM logic (`tree_math.py`), and core array-based node representations (`tree.py`).
- **Milestone 3**: RFC 9420 Key Schedule hash derivation (`keyschedule.py`) and immutable `EpochState` transitions exhibiting Forward Secrecy and Post-Compromise Security (`epoch.py`).
