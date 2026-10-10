# Security

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in `libvrf-js`, please report it privately by:

1. Opening a security advisory on GitHub (preferred)
2. Emailing the repository maintainer directly

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

## Security Considerations

This library implements Verifiable Random Functions (VRFs) which are cryptographic primitives. When using this library:

1. **Key Management**: Protect secret keys appropriately. Never commit them to version control.
2. **Random Number Generation**: This library uses Node.js's `crypto.randomBytes()` which is cryptographically secure.
3. **Side-Channel Attacks**: Equal-length byte comparisons use `crypto.timingSafeEqual` on Node.js (`bytesEqual`). A length mismatch returns immediately; serialized proof and key lengths are public. JavaScript `bigint` arithmetic (`modPow`, `modInverse`) is variable-time and is not used to compare secret material. Complete side-channel resistance is not guaranteed.
4. **Production Use**: This is a JavaScript port of Microsoft's libvrf. For production systems requiring maximum security, consider the original C++ implementation.

## Supported Versions

| Version | Security updates |
|---------|------------------|
| **1.2.x** (latest) | Yes |
| Older than 1.1.0 | No — upgrade to the latest release |

Security updates are provided for the latest released line only. See [CHANGELOG.md](CHANGELOG.md).

## Acknowledgments

This library is a port of [Microsoft's libvrf](https://github.com/Microsoft/libvrf). Security issues in the underlying cryptographic algorithms should be reported to both projects.

