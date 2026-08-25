# Repository tools

Go command-line tools follow
[`ADR-0003`](../docs/architecture/ADR-0003-command-line.md): Cobra and pflag
form the command foundation, while streams, options, execution, and printers
remain independently testable.

Repository-owned validation, generation, migration, and release tools live
here. New scripts require a stable command contract, tests, an owner, and a
documented retirement path.
