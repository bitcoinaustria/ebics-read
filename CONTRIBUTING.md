# Contributing

EBICSMIT is a clean-room project. Contributions must preserve its read-only
boundary and document their information sources.

Before opening a change:

1. Read `docs/clean-room.md` and `docs/scope.md`.
2. Do not inspect or derive code from a nonfree EBICS implementation.
3. Record protocol sources in `docs/provenance.md` before implementing from
   them.
4. Do not add payment initiation, uploads, BTU, or a generic order execution
   escape hatch.
5. Do not commit official schemas or code lists unless their redistribution
   rights have been documented and approved for this repository.
6. Add tests that demonstrate the read-only boundary remains fail-closed.

By contributing, you agree that your contribution is available under the MIT
License and that it was produced within these clean-room constraints.
