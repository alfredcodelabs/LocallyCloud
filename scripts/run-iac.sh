#!/usr/bin/env bash
# Deploys the same Terraform / SAM / Serverless projects against an already running emulator.
#   ./run-iac.sh lc     [terraform sam serverless]     # LocallyCloud on http://127.0.0.1:4566
#   ./run-iac.sh awsemu [terraform sam serverless]     # AWS Emulator on https://127.0.0.1:9297
# Env overrides: LC_ENDPOINT, EMU_ENDPOINT, EMU_HOME (HOME the aws-emulator was started with).
# Results: results/<target>.tsv; compare with ./compare-iac.sh
set -uo pipefail
here="${IAC_ROOT:-$(cd "$(dirname "$0")" && pwd)}"
target="${1:?target lc|awsemu}"; shift
tools=("$@"); [ ${#tools[@]} -eq 0 ] && tools=(terraform sam serverless)
case "$target" in lc|awsemu) ;; *) echo "unknown target $target" >&2; exit 2 ;; esac
for tool in "${tools[@]}"; do
  case "$tool" in terraform|sam|serverless) ;; *) echo "unknown tool $tool" >&2; exit 2 ;; esac
done
mkdir -p "$here/runs" "$here/results" || exit 1
work="$(mktemp -d "$here/runs/$target-XXXXXXXX")" || exit 1
run="${work##*-}"
run="${run,,}"
out="$work/results.tsv"; : > "$out"
log="$work/run.log"
failed=0
declare -A recorded=()

for v in "${!AWS_@}"; do unset "$v"; done
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 AWS_PAGER="" AWS_EC2_METADATA_DISABLED=true AWS_PROFILE=default
export SAM_CLI_TELEMETRY=0 SLS_TELEMETRY_DISABLED=1 SLS_NOTIFICATIONS_MODE=off CHECKPOINT_DISABLE=1
export TF_PLUGIN_CACHE_DIR="$here/.tfcache"; mkdir -p "$TF_PLUGIN_CACHE_DIR"
CURL=(curl -fsS --max-time "${IAC_HTTP_TIMEOUT:-30}")
configure_target() {
case "$target" in
  lc)
    export AWS_ENDPOINT_URL="${LC_ENDPOINT:-http://127.0.0.1:4566}"
    printf '[default]\nregion = us-east-1\n' > "$work/config"
    (umask 077; printf '[default]\naws_access_key_id = test\naws_secret_access_key = test\n' > "$work/credentials")
    export AWS_CONFIG_FILE="$work/config" AWS_SHARED_CREDENTIALS_FILE="$work/credentials"
    export IAC_SLS_HOST=http://127.0.0.1 IAC_SLS_PORT="${AWS_ENDPOINT_URL##*:}" ;;
  awsemu)
    emu="${EMU_HOME:-$here/../awsemu/home}/.aws/emulator/9297"
    [ -f "$emu/ca.pem" ] || { echo "aws-emulator not running with HOME=${EMU_HOME:-$here/../awsemu/home}" >&2; return 1; }
    export AWS_ENDPOINT_URL="${EMU_ENDPOINT:-https://127.0.0.1:9297}" AWS_CA_BUNDLE="$emu/ca.pem" NODE_EXTRA_CA_CERTS="$emu/ca.pem"
    export AWS_SHARED_CREDENTIALS_FILE="$emu/emulator_credentials" AWS_CONFIG_FILE="$emu/config"
    export IAC_SLS_HOST=https://127.0.0.1 IAC_SLS_PORT="${AWS_ENDPOINT_URL##*:}"
    CURL+=(--cacert "$emu/ca.pem") ;;
  *) echo "unknown target $target" >&2; exit 2 ;;
esac
}

record() {
  local tool="$1" name="$2" status="$3" seconds="$4" detail="$5"
  detail="$(printf '%s' "$detail" | tr '\t\r\n' '   ' | cut -c1-240)"
  printf '%s\t%s\t%s\t%s\t%s\n' "$tool" "$name" "$status" "$seconds" "$detail" | tee -a "$out"
  recorded["$tool/$name"]=1
  if [ "$status" != PASS ]; then failed=1; fi
}
step() {  # step <tool> <name> <command...>
  local tool="$1" name="$2"; shift 2
  local t0=$SECONDS status detail
  echo "### $tool/$name: $*" >> "$log"
  if detail="$("$@" 2>&1)"; then status=PASS; else status=FAIL; fi
  echo "$detail" >> "$log"
  detail="$(echo "$detail" | grep -iE -A 1 'error|fail|exception|denied|unsupported|not ' | head -4 | tr '\t\n' '  ' | cut -c1-240)"
  record "$tool" "$name" "$status" "$((SECONDS - t0))" "$detail"
  [ "$status" = PASS ]
}
# Invoked indirectly by step through its command arguments.
# shellcheck disable=SC2329
expect_missing() {
  local code="$1"; shift
  local detail
  if detail="$("$@" 2>&1)"; then
    echo "Resource still exists"
    return 1
  fi
  printf '%s\n' "$detail"
  [[ "$detail" == *"($code)"* ]] || return 1
  if [ "$code" = ValidationError ]; then
    [[ "$detail" == *"does not exist"* ]] || return 1
  fi
}
complete_rows() {
  local tool="$1" name
  local -a expected
  case "$tool" in
    terraform) expected=(init apply plan_no_changes lambda_invoke http_api_post eventbridge_to_sqs destroy destroyed_function_gone) ;;
    sam) expected=(deploy_create deploy_no_changes deploy_update http_api_post_after_update delete stack_gone) ;;
    serverless) expected=(deploy http_api_post http_api_list redeploy_no_changes remove) ;;
  esac
  for name in "${expected[@]}"; do
    if [[ ! -v "recorded[$tool/$name]" ]]; then
      record "$tool" "$name" BLOCKED 0 'Prerequisite failed; step was not executed'
    fi
  done
}
# Invoked indirectly by step through its command arguments.
# shellcheck disable=SC2329
expect_in() { local needle="$1"; shift; local got; got="$("$@")" || { echo "$got"; return 1; }; echo "$got"; grep -q -- "$needle" <<<"$got"; }
api_url() {  # local invoke URL: LocallyCloud documents /execute-api/<id>/<stage>; AWS Emulator returns a local ApiEndpoint
  if [ "$target" = lc ]; then echo "$AWS_ENDPOINT_URL/execute-api/$1/\$default"; else aws apigatewayv2 get-api --api-id "$1" --query ApiEndpoint --output text; fi
}

terraform_flow() {
  local d="$work/terraform"; cp -r "$here/terraform" "$d" || return 1
  local tf=(terraform -chdir="$d")
  step terraform init "${tf[@]}" init -input=false -no-color || return
  if ! step terraform apply "${tf[@]}" apply -input=false -no-color -auto-approve -var "suffix=$run"; then
    step terraform destroy "${tf[@]}" destroy -input=false -no-color -auto-approve -var "suffix=$run"
    return 1
  fi
  step terraform plan_no_changes "${tf[@]}" plan -input=false -no-color -detailed-exitcode -var "suffix=$run"
  local api fn q; api="$("${tf[@]}" output -raw api_id)"; fn="$("${tf[@]}" output -raw function_name)"; q="$("${tf[@]}" output -raw queue_url)"
  step terraform lambda_invoke expect_in 'stored.*direct' sh -c "aws lambda invoke --function-name $fn --cli-binary-format raw-in-base64-out --payload '{\"body\":\"{\\\"id\\\":\\\"direct\\\"}\"}' $work/tf-invoke.json >/dev/null && cat $work/tf-invoke.json"
  step terraform http_api_post expect_in 'stored.*tf' "${CURL[@]}" -X POST -H 'content-type: application/json' -d '{"id":"tf"}' "$(api_url "$api")/items"
  step terraform eventbridge_to_sqs expect_in 'iac.test' sh -c "aws events put-events --entries '[{\"Source\":\"iac.test\",\"DetailType\":\"t\",\"Detail\":\"{}\"}]' >/dev/null && aws sqs receive-message --queue-url $q --wait-time-seconds 10"
  step terraform destroy "${tf[@]}" destroy -input=false -no-color -auto-approve -var "suffix=$run" || return 1
  step terraform destroyed_function_gone expect_missing ResourceNotFoundException aws lambda get-function --function-name "$fn"
}

sam_flow() {
  [ -x "$here/.venv/bin/sam" ] || { record sam setup FAIL 0 'Missing SAM CLI'; return 1; }
  local sam="$here/.venv/bin/sam" d="$work/sam" stack="lcbench-sam-$run" bucket="lcbench-sam-$run"
  cp -r "$here/sam" "$d" || return 1
  step sam artifact_bucket aws s3api create-bucket --bucket "$bucket" || return 1
  local dep=("$sam" deploy --template-file "$d/template.yaml" --stack-name "$stack" --s3-bucket "$bucket" --capabilities CAPABILITY_IAM
             --no-confirm-changeset --no-progressbar --region us-east-1)
  step sam deploy_create "${dep[@]}" --parameter-overrides Greeting=v1 || { step sam delete "$sam" delete --no-prompts --stack-name "$stack" --region us-east-1; return; }
  step sam deploy_no_changes "${dep[@]}" --parameter-overrides Greeting=v1 --no-fail-on-empty-changeset
  if ! step sam deploy_update "${dep[@]}" --parameter-overrides Greeting=v2; then
    step sam delete "$sam" delete --no-prompts --stack-name "$stack" --region us-east-1
    return 1
  fi
  local api; api="$(aws cloudformation describe-stacks --stack-name "$stack" --query "Stacks[0].Outputs[?OutputKey=='ApiId'].OutputValue" --output text)"
  step sam http_api_post_after_update expect_in 'greeting.*v2' "${CURL[@]}" -X POST -H 'content-type: application/json' -d '{"id":"sam"}' "$(api_url "$api")/items"
  step sam delete "$sam" delete --no-prompts --stack-name "$stack" --region us-east-1 || return 1
  step sam stack_gone expect_missing ValidationError aws cloudformation describe-stacks --stack-name "$stack"
}

serverless_flow() {
  local d="$work/serverless" fixture="${IAC_SERVERLESS_FIXTURE:-$here/serverless-osls}"
  [ -x "$fixture/node_modules/.bin/osls" ] || { record serverless setup FAIL 0 'Missing Open Serverless dependencies: install the pinned osls fixture'; return 1; }
  step serverless toolchain node -e '
    const fs = require("node:fs");
    const path = require("node:path");
    const root = process.argv[1];
    const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json")));
    const installed = JSON.parse(fs.readFileSync(path.join(root, "node_modules/osls/package.json")));
    const expected = manifest.devDependencies?.osls;
    if (installed.name !== "osls" || !/^4\.[0-9]+\.[0-9]+$/.test(expected ?? "") || installed.version !== expected) {
      console.error("Expected pinned osls v4; installed version differs from fixture");
      process.exit(1);
    }
    console.log(JSON.stringify({cli: installed.name, version: installed.version}));
  ' "$fixture" || return 1
  mkdir -p "$d" || return 1
  find "$fixture" -mindepth 1 -maxdepth 1 ! -name node_modules ! -name .serverless ! -name .git -exec cp -r -t "$d" -- {} + || return 1
  ln -s "$fixture/node_modules" "$d/node_modules" || return 1
  local sls=(env -C "$d" "$d/node_modules/.bin/osls")
  step serverless deploy "${sls[@]}" deploy --stage local || { step serverless remove "${sls[@]}" remove --stage local; return; }
  local api; api="$(aws apigatewayv2 get-apis --query "Items[?Name=='local-lcbench'].ApiId | [0]" --output text)"
  local url; url="$(api_url "$api")"
  if step serverless http_api_post expect_in '"id":"sls"' "${CURL[@]}" -X POST -d '{"id":"sls"}' "$url/items"; then
    step serverless http_api_list expect_in '"sls"' "${CURL[@]}" "$url/items"
  fi
  step serverless redeploy_no_changes "${sls[@]}" deploy --stage local
  step serverless remove "${sls[@]}" remove --stage local
}

if configure_target; then
  for t in "${tools[@]}"; do
    case "$t" in
      terraform) terraform_flow || failed=1 ;;
      sam) sam_flow || failed=1 ;;
      serverless) serverless_flow || failed=1 ;;
    esac
    complete_rows "$t"
  done
else
  for t in "${tools[@]}"; do
    record "$t" setup FAIL 0 'Target configuration failed'
    complete_rows "$t"
  done
fi
cp -- "$out" "$here/results/$target.tsv" || exit 1
echo "log: $log"
exit "$failed"
