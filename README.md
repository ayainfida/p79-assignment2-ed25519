# Assignment 2: Elliptic Curve Signatures (Ed25519)

This assignment implements Ed25519 digital signature scheme from scratch in Python, following RFC 8032. It supports both standard point addition and optimized version using extended projective coordinates.

## ⚠️ Security Disclaimer

**This implementation is for educational purposes only (in particular, submission for Assignment 2 of P79: Cryptography and Protocol Engineering offered at the University of Cambridge) and is NOT suitable for production use.**

## Features

- **Two point addition methods**: Standard coordinates and Extended projective coordinates
- **Complete Ed25519 API**: Key generation, signing, and signature verification
- **RFC 8032 compliance**: All test vectors pass
- **Project Wycheproof compliance**: All test vectors pass
- **Comprehensive testing**: RFC vectors, Wycheproof, algorithm agreement, API validation, encoding, field operations, and group laws

## Repo Structure

```
ed25519/             # Core implementation
├── ed25519.py       # Main Ed25519 API with algorithm selection
├── point.py         # Point (affine) and ExtendedPoint (projective) classes
├── field.py         # Field arithmetic (ModInt base, FieldElement, Field_q)
├── methods.py       # Double-and-add scalar multiplication
├── encoding.py      # Point compression/decompression, scalar clamping
├── primitives.py    # Type-safe wrappers (PrivateKey, PublicKey, Signature, Message)
└── defaults.py      # Curve parameters and constants

tests/                          # Test suite
├── test_rfc_8032_vectors.py    # RFC 8032 Section 7.1 test vectors
├── test_wyche_proof_vectors.py # Wycheproof external test vectors
├── test_agreement.py           # Algorithm agreement validation
├── test_api.py                 # API type and length validation
├── test_field.py               # Field operation properties
├── test_group_law.py           # Point operation correctness
└── test_encoding.py            # Encoding/decoding edge cases

examples/
└── demo_ed25519.py  # Ed25519 signature demo

report/
└── P79_mafr2_A2.pdf  # report
```

## Setup

You will need to install the following:

- [uv](https://docs.astral.sh/uv/getting-started/installation/)
- [Docker](https://docs.docker.com/get-docker/)

## Development

For local development, clone the repository and let `uv` create a virtual environment with the required dependencies.

```bash
git clone https://github.com/ayainfida/p79-assignment2-ed25519.git
cd p79-assignment2-ed25519
uv sync
```

The `run.sh` script builds and runs the Docker image. It executes the type checker and linter during the build process and then runs the unit tests in a container.

```bash
./run.sh
```

You can run the type checker, linter, and the unit tests locally as well:

```bash
uv run ty check      # Static type checking
uv run ruff check    # Linting
uv run -m unittest   # Run all tests
```

### Running the Demo

The repo includes an Ed25519 signature demo that supports two types of point addition:

```bash
# Using standard coordinated (default)
python -m examples.demo_ed25519

# Using extended coordinates (faster)
python -m examples.demo_ed25519 -f
```

This generates a random key pair for Alice, signs a message, and verifies the signature.

### Running Specific Test Suites

```bash
python -m unittest tests.test_rfc_8032_vectors     # RFC 8032 Section 7.1 test vectors
python -m unittest tests.test_wyche_proof_vectors  # Wycheproof edge cases
python -m unittest tests.test_encoding -v          # Encoding/decoding
```


The API allows selection of the appropriate algorithm for point addition (default is standard `Point`). You can use the Ed25519 API in your own Python code as follows:

```python
from ed25519 import ED25519, ED25519ScalarMultAlgorithm, PrivateKey, PublicKey, Message, Signature

# Ed25519 using standard point addition
ed25519 = ED25519(ED25519ScalarMultAlgorithm.SCALAR_MULT)

# Ed25519 using fast point addition
ed25519_fast = ED25519(ED25519ScalarMultAlgorithm.FAST_SCALAR_MULT)
```

## References

- [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/rfc/rfc8032)
- [Twisted Edwards Curves Revisited](https://eprint.iacr.org/2008/522) by Hisil et al.
- [Project Wycheproof: Testing crypto libraries against known attacks](https://github.com/google/wycheproof)
## License

MIT License - See [LICENSE](LICENSE) file for details.
