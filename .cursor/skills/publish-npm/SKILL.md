---
name: publish-npm
description: >-
  Build tcx-wasm, bump version, and publish to npm. Use when the user says
  "publish", "发布", "npm publish", "publish-npm", or asks to release a new
  version of the @consenlabs/tcx-wasm package.
---

# Publish @consenlabs/tcx-wasm to npm

End-to-end workflow: build optimized WASM, bump version, and publish.

## Workflow

### Step 1 — Build optimized WASM + NPM package

Run in the workspace root:

```bash
make build-npm
```

This compiles tcx-wasm in release mode with LTO + Oz, copies artifacts to
`publish/npm/`, and runs `wasm-opt` if available. Wait for it to complete
and confirm the output shows `NPM package built in publish/npm/` with a
`.wasm` file size.

If the build fails, stop and report the error.

### Step 2 — Determine new version

Read the current version from `publish/npm/package.json` (the `version`
field). Parse it as `major.minor.patch`.

Compute a default suggestion: **minor + 1** with patch reset to 0
(e.g. `0.2.0` → `0.3.0`).

Ask the user to confirm or enter a custom version using the AskQuestion
tool:

```
Prompt: "Current version is X.Y.Z. Enter the new version (default: X.(Y+1).0):"
Options:
  - default  → "X.(Y+1).0 (minor bump)"
  - patch    → "X.Y.(Z+1) (patch bump)"
  - major    → "(X+1).0.0 (major bump)"
  - custom   → "I'll type a custom version"
```

If the user picks "custom", ask them to type it in a follow-up message.

### Step 3 — Update version in both files

Update the version string in **two** files:

| File | Field |
|------|-------|
| `publish/npm/package.json` | `"version": "..."` |
| `token-core/tcx-wasm/Cargo.toml` | `version = "..."` |

Use the StrReplace tool for both. Do NOT change any other fields.

### Step 4 — Ask for OTP and publish

npm requires a one-time password for `@consenlabs` scoped packages.

Ask the user for the OTP code:

```
Prompt: "Enter your npmjs OTP code to publish:"
```

Wait for the user's response, then run:

```bash
cd publish/npm && npm publish --otp <OTP>
```

If the publish fails due to an expired OTP, ask the user for a new one and
retry once.

### Step 5 — Report result

After successful publish, report:

- Published package name and version
- npm URL: `https://www.npmjs.com/package/@consenlabs/tcx-wasm`

## Important

- **Never** publish without an explicit OTP from the user.
- **Never** modify files beyond the two version fields listed above.
- If the build step fails, stop immediately — do not bump the version.
- The `make build-npm` command requires `wasm-pack` and `llvm` to be
  installed. If missing, tell the user to install them first.
