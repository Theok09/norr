# Configuration Semantics

Core sections:
- node
- identity
- peers
- routing
- transport
- qos
- fec
- observability

## Implemented today

The parser in `src/config.cpp` accepts `node`, `identity`, `network`,
`transport`, `qos`, `fec` and `observability`.

`peers` and `routing` are **not** accepted yet and a configuration using them
is rejected as an unknown section. They are deliberately absent: a peer entry
needs a public key format and an allowed-IP prefix model, both of which belong
to Phase 2, and accepting a section the rest of the program ignores would be
worse than refusing it. The `network` section is implemented and is not listed
above because the section list predates it.

For every option define:
- type
- default
- allowed range
- restart/reload behavior
- security impact
- performance impact
