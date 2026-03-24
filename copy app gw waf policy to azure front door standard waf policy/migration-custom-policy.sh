#!/bin/bash

set -euo pipefail

# --- Settings ---
# --- source and destination policy details ---
SOURCE_RG="rg-demo-colo"
# this is application gateway WAF policy with custom rules to copy from
SOURCE_POLICY="waf-appgw"
DEST_RG="rg-demo-colo"
# this is front door WAF policy to copy rules to
DEST_POLICY="forafd"

# --- Color logs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1" >&2
}

clean_tsv() {
  local v="$1"
  # Azure CLI on Windows often emits CRLF in TSV output; remove hidden CR.
  v="${v//$'\r'/}"
  printf '%s' "$v"
}

require_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "Missing required command: $cmd"
    exit 1
  fi
}

check_frontdoor_cli() {
  if ! az network front-door waf-policy rule -h >/dev/null 2>&1; then
    log_error "Front Door WAF rule command not found."
    log_info "Install extension: az extension add --name front-door --allow-preview true --yes"
    exit 1
  fi
}

map_rule_type() {
  local t="$1"
  case "$t" in
    MatchRule|matchrule) echo "MatchRule" ;;
    RateLimitRule|ratelimitrule) echo "RateLimitRule" ;;
    *) echo "MatchRule" ;;
  esac
}

map_action() {
  local a="$1"
  case "$a" in
    Allow|allow) echo "Allow" ;;
    Log|log) echo "Log" ;;
    Redirect|redirect) echo "Redirect" ;;
    *) echo "Block" ;;
  esac
}

map_rate_limit_duration() {
  local d="$1"
  case "$d" in
    OneMin|onemin|1) echo "1" ;;
    FiveMins|fivemins|5) echo "5" ;;
    *) echo "" ;;
  esac
}

normalize_match_variable() {
  local mv="$1"
  case "$mv" in
    RequestHeaders.*) echo "RequestHeader.${mv#RequestHeaders.}" ;;
    RequestHeaders) echo "RequestHeader" ;;
    RequestCookies.*) echo "Cookies.${mv#RequestCookies.}" ;;
    RequestCookies) echo "Cookies" ;;
    *) echo "$mv" ;;
  esac
}

# --- Validation ---
require_command az
check_frontdoor_cli

log_info "Validating source WAF policy..."
if ! az network application-gateway waf-policy show \
  --resource-group "$SOURCE_RG" \
  --name "$SOURCE_POLICY" \
  --only-show-errors >/dev/null; then
  log_error "Source policy not found: $SOURCE_POLICY in $SOURCE_RG"
  exit 1
fi

log_info "Validating destination Front Door WAF policy..."
if ! az network front-door waf-policy show \
  --resource-group "$DEST_RG" \
  --name "$DEST_POLICY" \
  --only-show-errors >/dev/null; then
  log_error "Destination policy not found: $DEST_POLICY in $DEST_RG"
  exit 1
fi

# Read custom rule names from source AppGW policy.
mapfile -t rule_names < <(az network application-gateway waf-policy show \
  --resource-group "$SOURCE_RG" \
  --name "$SOURCE_POLICY" \
  --query "customRules[].name" \
  --output tsv | tr -d '\r')

if [ "${#rule_names[@]}" -eq 0 ]; then
  log_warn "No custom rules found in source policy."
  exit 0
fi

log_info "Found ${#rule_names[@]} rule(s). Starting migration..."

migrate_failed=0

for rule_name in "${rule_names[@]}"; do
  rule_name=$(clean_tsv "$rule_name")
  [ -z "$rule_name" ] && continue

  # Base rule properties.
  rule_priority=$(az network application-gateway waf-policy show \
    --resource-group "$SOURCE_RG" \
    --name "$SOURCE_POLICY" \
    --query "customRules[?name=='$rule_name']|[0].priority" \
    --output tsv)
  rule_priority=$(clean_tsv "$rule_priority")

  src_action=$(az network application-gateway waf-policy show \
    --resource-group "$SOURCE_RG" \
    --name "$SOURCE_POLICY" \
    --query "customRules[?name=='$rule_name']|[0].action" \
    --output tsv)
  src_action=$(clean_tsv "$src_action")

  src_type=$(az network application-gateway waf-policy show \
    --resource-group "$SOURCE_RG" \
    --name "$SOURCE_POLICY" \
    --query "customRules[?name=='$rule_name']|[0].ruleType" \
    --output tsv)
  src_type=$(clean_tsv "$src_type")

  rule_action=$(map_action "$src_action")
  rule_type=$(map_rule_type "$src_type")

  mapfile -t cond_operators < <(az network application-gateway waf-policy show \
    --resource-group "$SOURCE_RG" \
    --name "$SOURCE_POLICY" \
    --query "customRules[?name=='$rule_name']|[0].matchConditions[].operator" \
    --output tsv | tr -d '\r')

  if [ "${#cond_operators[@]}" -eq 0 ]; then
    log_warn "Rule $rule_name has no match conditions. Skipping."
    continue
  fi

  log_info "Migrating rule: $rule_name (priority=$rule_priority, action=$rule_action, type=$rule_type)"

  # Ensure deterministic reruns.
  az network front-door waf-policy rule delete \
    --resource-group "$DEST_RG" \
    --policy-name "$DEST_POLICY" \
    --name "$rule_name" \
    --only-show-errors >/dev/null 2>&1 || true

  created=false

  for c in "${!cond_operators[@]}"; do
    operator="${cond_operators[$c]}"

    negate=$(az network application-gateway waf-policy show \
      --resource-group "$SOURCE_RG" \
      --name "$SOURCE_POLICY" \
      --query "customRules[?name=='$rule_name']|[0].matchConditions[$c].negationConditon" \
      --output tsv)
    negate=$(clean_tsv "$negate")

    # Backward compatibility if property name differs.
    if [ -z "$negate" ] || [ "$negate" = "null" ]; then
      negate=$(az network application-gateway waf-policy show \
        --resource-group "$SOURCE_RG" \
        --name "$SOURCE_POLICY" \
        --query "customRules[?name=='$rule_name']|[0].matchConditions[$c].negationCondition" \
        --output tsv)
      negate=$(clean_tsv "$negate")
    fi

    [ -z "$negate" ] && negate="false"

    mapfile -t values < <(az network application-gateway waf-policy show \
      --resource-group "$SOURCE_RG" \
      --name "$SOURCE_POLICY" \
      --query "((customRules[?name=='$rule_name']|[0].matchConditions[$c].matchValues) || [])[]" \
      --output tsv | tr -d '\r')

    if [ "${#values[@]}" -eq 0 ]; then
      log_warn "Rule $rule_name condition $c has no values. Skipping condition."
      continue
    fi

    mapfile -t transforms < <(az network application-gateway waf-policy show \
      --resource-group "$SOURCE_RG" \
      --name "$SOURCE_POLICY" \
      --query "((customRules[?name=='$rule_name']|[0].matchConditions[$c].transforms) || [])[]" \
      --output tsv | tr -d '\r')

    mapfile -t var_names < <(az network application-gateway waf-policy show \
      --resource-group "$SOURCE_RG" \
      --name "$SOURCE_POLICY" \
      --query "customRules[?name=='$rule_name']|[0].matchConditions[$c].matchVariables[].variableName" \
      --output tsv | tr -d '\r')

    if [ "${#var_names[@]}" -eq 0 ]; then
      log_warn "Rule $rule_name condition $c has no match variables. Skipping condition."
      continue
    fi

    for v in "${!var_names[@]}"; do
      var_name="${var_names[$v]}"

      selector=$(az network application-gateway waf-policy show \
        --resource-group "$SOURCE_RG" \
        --name "$SOURCE_POLICY" \
        --query "customRules[?name=='$rule_name']|[0].matchConditions[$c].matchVariables[$v].selector" \
        --output tsv)
      selector=$(clean_tsv "$selector")

      match_var="$var_name"
      if [ -n "$selector" ] && [ "$selector" != "null" ]; then
        match_var="$var_name.$selector"
      fi
      match_var=$(normalize_match_variable "$match_var")

      if [ "$created" = false ]; then
        create_cmd=(
          az network front-door waf-policy rule create
          --resource-group "$DEST_RG"
          --policy-name "$DEST_POLICY"
          --name "$rule_name"
          --priority "$rule_priority"
          --rule-type "$rule_type"
          --action "$rule_action"
          --match-variable "$match_var"
          --operator "$operator"
          --values
        )
        create_cmd+=("${values[@]}")

        if [ "$negate" = "true" ] || [ "$negate" = "True" ]; then
          create_cmd+=(--negate true)
        fi

        if [ "${#transforms[@]}" -gt 0 ]; then
          create_cmd+=(--transforms)
          create_cmd+=("${transforms[@]}")
        fi

        if [ "$rule_type" = "RateLimitRule" ]; then
          src_duration=$(az network application-gateway waf-policy show \
            --resource-group "$SOURCE_RG" \
            --name "$SOURCE_POLICY" \
            --query "customRules[?name=='$rule_name']|[0].rateLimitDuration" \
            --output tsv)
          src_duration=$(clean_tsv "$src_duration")

          src_threshold=$(az network application-gateway waf-policy show \
            --resource-group "$SOURCE_RG" \
            --name "$SOURCE_POLICY" \
            --query "customRules[?name=='$rule_name']|[0].rateLimitThreshold" \
            --output tsv)
          src_threshold=$(clean_tsv "$src_threshold")

          mapped_duration=$(map_rate_limit_duration "$src_duration")
          if [ -n "$mapped_duration" ] && [ -n "$src_threshold" ] && [ "$src_threshold" != "null" ]; then
            create_cmd+=(--rate-limit-duration "$mapped_duration" --rate-limit-threshold "$src_threshold")
          else
            log_warn "Rule $rule_name is RateLimitRule but duration/threshold missing. Creating as MatchRule."
            create_cmd=(
              az network front-door waf-policy rule create
              --resource-group "$DEST_RG"
              --policy-name "$DEST_POLICY"
              --name "$rule_name"
              --priority "$rule_priority"
              --rule-type MatchRule
              --action "$rule_action"
              --match-variable "$match_var"
              --operator "$operator"
              --values
            )
            create_cmd+=("${values[@]}")
            if [ "$negate" = "true" ] || [ "$negate" = "True" ]; then
              create_cmd+=(--negate true)
            fi
            if [ "${#transforms[@]}" -gt 0 ]; then
              create_cmd+=(--transforms)
              create_cmd+=("${transforms[@]}")
            fi
          fi
        fi

        if ! "${create_cmd[@]}" --only-show-errors >/dev/null; then
          log_error "Failed to create rule: $rule_name"
          migrate_failed=1
          created=false
          break
        fi

        created=true
        log_info "  -> Created rule with first condition ($match_var, $operator)"
      else
        add_cmd=(
          az network front-door waf-policy rule match-condition add
          --resource-group "$DEST_RG"
          --policy-name "$DEST_POLICY"
          --name "$rule_name"
          --match-variable "$match_var"
          --operator "$operator"
          --values
        )
        add_cmd+=("${values[@]}")

        if [ "$negate" = "true" ] || [ "$negate" = "True" ]; then
          add_cmd+=(--negate true)
        fi

        if [ "${#transforms[@]}" -gt 0 ]; then
          add_cmd+=(--transforms)
          add_cmd+=("${transforms[@]}")
        fi

        if ! "${add_cmd[@]}" --only-show-errors >/dev/null; then
          log_error "Failed to add condition for rule $rule_name ($match_var, $operator)"
          migrate_failed=1
        else
          log_info "  -> Added condition ($match_var, $operator)"
        fi
      fi
    done
  done

  if [ "$created" = false ]; then
    log_error "Rule $rule_name was not created due to condition errors."
    migrate_failed=1
  fi
done

mapfile -t dest_rule_names < <(az network front-door waf-policy show \
  --resource-group "$DEST_RG" \
  --name "$DEST_POLICY" \
  --query "customRules.rules[].name" \
  --output tsv | tr -d '\r')

source_count="${#rule_names[@]}"
dest_count="${#dest_rule_names[@]}"

log_info "Migration completed. Source rules: $source_count, Destination rules: $dest_count"

log_info "Source rule names: ${rule_names[*]}"
log_info "Destination rule names: ${dest_rule_names[*]}"

if [ "$source_count" -ne "$dest_count" ] || [ "$migrate_failed" -ne 0 ]; then
  log_error "Verification failed: destination policy does not fully match source policy."
  exit 1
fi

log_info "Verification passed: destination policy matches source rule count."
