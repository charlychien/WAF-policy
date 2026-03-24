# App Gateway WAF -> Front Door WAF Rule Copy Script (No jq)

This folder contains a Bash script that copies custom WAF rules from an Azure Application Gateway WAF policy to an Azure Front Door (Standard/Premium) WAF policy.

Script file: `migration-custom-policy.sh`

## What This Script Does

- Reads custom rules from source App Gateway WAF policy.
- Recreates each rule in destination Front Door WAF policy.
- Copies match conditions, values, transforms, and negate flag.
- Maps App Gateway waf rule variable names to Front Door equivalents when needed:
  - `RequestHeaders.*` -> `RequestHeader.*`
  - `RequestCookies.*` -> `Cookies.*`
- Supports rerun safely (deletes destination rule before recreate).
- Verifies result at the end:
  - compares source and destination rule counts
  - prints both rule-name lists
  - exits non-zero if mismatch or migration errors occur

## Prerequisites

- Azure CLI installed and logged in.
- Bash shell (Git Bash or WSL Bash).
- Front Door CLI extension available:

```bash
az extension add --name front-door --allow-preview true --yes
```

- Access permissions for both policies:
  - Read on source App Gateway WAF policy.
  - Write on destination Front Door WAF policy.

## Configuration

Edit the variables at the top of `migration-custom-policy.sh`:

```bash
SOURCE_RG="your-source-rg"
SOURCE_POLICY="your-source-appgw-waf-policy-name"
DEST_RG="your-dest-rg"
DEST_POLICY="your-dest-afd-waf-policy-name"
```

## Usage

From this folder:

```bash
chmod +x migration-custom-policy.sh.sh
./migration-custom-policy.sh.sh
```

## Exit Codes

- `0`: Migration and verification passed.
- `1`: Migration failed, verification mismatch, or missing prerequisites.

## Notes and Behavior

- The script uses only Azure CLI `--query` and shell parsing (no jq required).
- Windows CRLF in TSV output is normalized internally.
- If a source rule has unsupported/invalid condition data for Front Door, that rule may fail and script exits with code `1`.
- Rule matching logic differences can exist between App Gateway and Front Door; review critical security rules after migration.

## Quick Validation Commands

Check source custom rules:

```bash
az network application-gateway waf-policy show \
  -g "$SOURCE_RG" -n "$SOURCE_POLICY" \
  --query "customRules[].name" -o tsv
```

Check destination custom rules:

```bash
az network front-door waf-policy show \
  -g "$DEST_RG" -n "$DEST_POLICY" \
  --query "customRules.rules[].name" -o tsv
```
