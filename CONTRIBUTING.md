# Contributing

Read `AGENTS.md`, `docs/clean-room-sources.md`, `docs/protocol-scope.md`, and
`docs/threat-model.md` before changing protocol code.

Every contribution must:

1. use only permitted public sources and record them in
   `docs/clean-room-sources.md` before implementation;
2. preserve the fixed read-only order set and avoid raw-order/request escape
   hatches;
3. keep real credentials, identifiers, XML, certificates, and financial data
   out of code, tests, issues, command arguments, and public CI;
4. include focused positive and negative tests;
5. pass formatting, lint, strict typing, tests, build/install, and dependency
   audit checks; and
6. include a Developer Certificate of Origin sign-off (`git commit -s`).

Do not vendor official EBICS artifacts unless a maintainer has documented clear
redistribution and sublicensing permission. Do not weaken validation to make a
fixture or bank pass.

Contributions are licensed under MIT and certify compliance with the
[Developer Certificate of Origin 1.1](https://developercertificate.org/).
