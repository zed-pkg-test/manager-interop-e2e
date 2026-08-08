# Canonical Devbox and Flox export certification

This contract independently certifies the exact `zed-pkg/zed-cli` candidate
that exposes deterministic Devbox and Flox generation through both:

```console
zed env export devbox ...
zed env export flox ...
zed-env-export devbox ...
zed-env-export flox ...
```

The product candidate is pinned in
[`canaries/devbox-flox-export.json`](../canaries/devbox-flox-export.json). A
later product commit invalidates the evidence until the pin is updated and the
complete matrix reruns.

## Why this repository

`zed-pkg-test/manager-interop-e2e` is the specialized test-organization owner
for mise, asdf, Devbox, Flox, Nix, and manager import/export compatibility. The
canary is additive to the broad `zed-pkg-e2e` fleet and does not modify the
generated fleet manifest, source-pin inventory, or release-gated integration
workflow.

## Runtime boundary

The harness runs the exact compiled `zed` and `zed-env-export` binaries with:

- an empty executable search path;
- disposable project, home, config, and Zed-package directories;
- loopback-only failing proxy endpoints;
- no manager binary;
- no GitHub, registry, Cloudflare, R2, or package-manager credential; and
- no persistent namespace.

Successful generation under that environment proves that runtime export does
not invoke Devbox, Flox, Nix, a shell, a package resolver, or a network service.
Cargo may use its ordinary dependency sources while the reviewed candidate is
built; that build activity is not represented as a runtime-network claim.

## Certified behavior

The Ubuntu, macOS, and Windows jobs require:

1. exact candidate checkout identity;
2. committed rustfmt cleanliness;
3. focused renderer and compiled-CLI tests;
4. strict focused Clippy with warnings denied;
5. locked release builds of both executable surfaces; and
6. an independent standard-library Python black-box contract.

The black-box contract verifies:

- byte-identical canonical/staged stdout and stderr;
- byte-identical manager files and Zed-owned receipts;
- independent parsing of Devbox JSON and Flox TOML;
- exact package, platform, version, and frozen-install activation projection;
- independent SHA-256 validation of output and receipt identities;
- deterministic repeated exports and `changed=false` idempotence;
- custom path and flags-to-environment parity;
- atomic refusal of differing human-owned outputs and receipts;
- project-root containment and output/receipt path separation;
- rejection of mise-only options on Devbox/Flox;
- rejection of unsupported export managers; and
- rejection of unsupported Flox platforms before any state is written.

## Deliberate non-claims

This lane does not certify:

- `devbox.lock` or Flox `manifest.lock` generation;
- execution of a generated manager environment;
- manager-native offline replay;
- Nix evaluation of the emitted manager configuration;
- semantic merging of hand-authored manager files; or
- import/export/import equality for unsupported manager-owned fields.

Those require manager binaries and separate immutable native-lock fixtures. A
green result here certifies deterministic projection and conflict-safe Zed
ownership only.

## Evidence

Each platform uploads one commit-addressed JSON artifact under schema:

```text
zed-pkg-test/devbox-flox-export-canary/v1
```

The report contains the exact product SHA, platform, binary versions, claims,
and bounded case results. It contains no environment value, source contents,
credential, signed URL, or generated manager file.
