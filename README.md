# pure-mls

pure-mls is a zero-dependency, pure Python implementation of the Messaging Layer Security (MLS) protocol ([RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)).

## Philosophy
The goal is **Absolute Purity**: 
- No compiled bindings (no Rust, C++ or FFI).
- Operates natively in any Python 3 environment.
- Suitable for zero-friction edge computing and standard backend runtimes.
- Built on principles of [Plausible Deniability and Zero-Knowledge](docs/00_MANIFESTO.md).

## License
This project is licensed under the GNU General Public License v3.0 (GPLv3).
