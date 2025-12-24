# Security Model

> **Status**: This document is a placeholder. A comprehensive threat model is forthcoming.

## Principles

1. **Defense in depth**: Multiple overlapping security layers (namespaces, Landlock, seccomp-bpf, capability dropping)
2. **Deny by default**: Sandboxes start with minimal permissions; access is explicitly granted
3. **Fail secure**: When in doubt, deny access and surface errors clearly

## Security-Sensitive Changes

Any changes that weaken the security stance must:
1. Be discussed before implementation
2. Document the rationale in this file
3. Reference this documentation explicitly in code comments

## Threat Model

_To be documented: adversary capabilities, trust boundaries, attack surfaces, and mitigations._

## References

- See `Implementation notes.md` for security layer implementation details
- See `ARCHITECTURE.md` for component trust boundaries