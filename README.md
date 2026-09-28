# AGENTS APP foundation repository (synthetic, public)

Synthetic, non-production repository used to prove the AGENTS APP trust path:
owner-approved contract -> Builder (Claude Code, isolated) -> PR by the agent GitHub App -> `gate` (GitHub Actions) ->
blind Verifier (Codex, isolated, no repository access) -> owner decision (approval + merge).

Protected paths (owner review + tamper gate): `oracle/`, `baselines/`, `tasks/`, `.github/`, `CODEOWNERS`, `gate/`, `policy.json`.
Nothing here is a real credential; the `CANARY` Actions secret is a synthetic value used only by the canary scan.
