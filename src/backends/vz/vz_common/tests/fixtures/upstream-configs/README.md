# Upstream policy config fixtures

Vendored from [microsoft/mxc](https://github.com/microsoft/mxc)
`tests/configs/` at commit `692275b84eaa3f83cd8582dc774bc5f354f46ccf`
(MIT licensed, © Microsoft Corporation).

Selection criterion: every config whose `version` is `0.8.0-*` — i.e. the
fixtures written against the current wire surface that
`schemas/dev/mxc-config.schema.0.8.0-dev.json` describes. Older fixtures
(`0.6.0-alpha` and earlier) go through upstream's version-specific contract
adapters (`config_contract_adapters/`) and are intentionally excluded: this
crate models only the current surface.

Files from subdirectories keep their path with `/` replaced by `__`
(e.g. `base_container_ui_configs__01_disable_true.json`).

Used by `tests/upstream_conformance.rs` as a parse-conformance smoke suite:
every fixture must deserialize into `vz_common::policy::Policy`. This is the
cross-backend portability contract from the build plan (Phase 5) tested at
the parse level — a vz policy is the same document with `containment`
swapped, so the vz structs must accept everything the other backends accept.

Do not edit these files; refresh them from upstream instead.
