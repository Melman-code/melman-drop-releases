# Automatic release publishing — MELMAN Drop

This PUBLIC repository contains only signed installers, public updater key, release metadata and a feed gate. Original source and signing key remain in the PRIVATE `Melman-code/melman-drop`.

- Private build creates a **draft** GitHub Release with signed NSIS EXE, `.sig`, `SHA256.txt`.
- Owner reviews it and clicks **Publish release**. Draft files are not a live updater.
- This workflow is triggered only by publication of a prerelease. It downloads the published EXE, verifies the Ed25519 minisign signature using the pinned public key (no private key), checks signed SemVer, SHA256.txt, downloads the public asset again, and rejects downgrades.
- Only after all checks pass does the workflow update `channels/beta.json`. The stable feed is NEVER changed by this workflow.
- If a check fails, the GitHub release remains visible but the channel remains unchanged; inspect Actions and fix the release safely. Never bypass signature verification.
- Never grant the PRIVATE signer key to this PUBLIC repository or commit any private credentials.
- The workflow intentionally has no `workflow_dispatch`, `push`, and no release creation permissions beyond the minimal GitHub Actions token. No public publication happens automatically from source code commits.
