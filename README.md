# vcs-scan

Security checks and a 0–100 score for apps written by AI. The same checks VCS runs before an app can go live.

| Check | Weight | Critical |
|---|---|---|
| Secrets in code | 25 | yes |
| Network egress outside approved connectors | 20 | yes |
| Dependencies (pinned, not denied) | 15 | |
| Permission scope (`vcs.json`) | 15 | |
| Unsafe code patterns | 15 | |
| Company policy (name, owner) | 10 | |

An app goes live only if it scores **80 or more** and **every critical check passes**.

## CLI

```
npx @vcs/scan ./my-app
npx @vcs/scan ./my-app --bar=90 --json
```

Exit code `0` = cleared, `1` = blocked.

## GitHub Action

```yaml
- uses: VibeCodeStore/vcs-scan@v0
  with:
    path: ./my-app
    bar: 80
```

## The app manifest (`vcs.json`)

```json
{
  "name": "expense-tracker",
  "owner": "ops@company.com",
  "scopes": ["expenses:read", "expenses:write"],
  "connectors": ["api.company.internal"]
}
```

## Limits

Pattern-based checks catch common mistakes, not every attack. VCS layers them with sandboxing, the access rule ([vcs-policy](https://github.com/VibeCodeStore/vcs-policy)) and human review.

## All VCS open-source repos

| Repo | What it is |
|---|---|
| [vcs-policy](https://github.com/VibeCodeStore/vcs-policy) | The access rule: requested ∩ approved ∩ role |
| [vcs-scan](https://github.com/VibeCodeStore/vcs-scan) | Security checks and a 0–100 score, as a CLI and GitHub Action |
| [vcs-sdk](https://github.com/VibeCodeStore/vcs-sdk) | How apps reach approved company data |
| [vcs-connectors](https://github.com/VibeCodeStore/vcs-connectors) | Connector spec and reference connectors |
| [vcs-templates](https://github.com/VibeCodeStore/vcs-templates) | Starter apps |
| [vcs-solana](https://github.com/VibeCodeStore/vcs-solana) | Solana client: Sign In With Solana, approval proofs, $VCS token helpers |
| [vcs-attest](https://github.com/VibeCodeStore/vcs-attest) | Solana attestation program (unaudited, devnet) |

Part of [VCS, the Vibe Code Store](https://vibecodestore.com).
