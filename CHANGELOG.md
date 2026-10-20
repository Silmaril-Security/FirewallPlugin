# Release notes

## 1.2.7 (unreleased)

The packaged configuration guide matches the host manifest: `timeoutMs` is a JSON integer from 250 through 10000 milliseconds; omission uses 2500. Fractional and out-of-range values are rejected by the host. The documentation correction is already on main but is absent from npm 1.2.6.

The package and runtime provenance identify version 1.2.7. Publishing requires a separate authorized release; npm 1.2.6 remains the current published package until then.
