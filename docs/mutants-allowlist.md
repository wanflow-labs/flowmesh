# Equivalent-mutant allowlist

Mutants that `cargo mutants` reports as surviving but that change no behavior. Each entry gives its reason. Anything not on this list that survives counts as a gap in tests or observations (design doc §5.2).

| crate | Location | Mutation | Why it is equivalent |
|---|---|---|---|
| flowmesh-dns | `parse_ptr`: `(pair[0] << 4) \| pair[1]` | `\|` → `^` | `pair[0] << 4` only occupies the high 4 bits, and `pair[1]` (one hex digit, < 16) only the low 4 bits; the two never overlap, so OR and XOR give the same result |
