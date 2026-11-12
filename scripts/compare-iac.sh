#!/usr/bin/env bash
# Prints a Markdown table comparing results/lc.tsv and results/awsemu.tsv.
cd "${IAC_ROOT:-$(dirname "$0")}/results" || exit 1
python3 -I - "$@" <<'PY'
import csv
import sys
from collections import Counter
expected = {
    "terraform": "init apply plan_no_changes lambda_invoke http_api_post eventbridge_to_sqs destroy destroyed_function_gone".split(),
    "sam": "deploy_create deploy_no_changes deploy_update http_api_post_after_update delete stack_gone".split(),
    "serverless": "deploy http_api_post http_api_list redeploy_no_changes remove".split(),
}
tools = sys.argv[1:] or list(expected)
if any(tool not in expected for tool in tools):
    sys.exit("Unknown tool; use terraform, sam or serverless")
rows, order = {}, []
for tool in tools:
    order.extend((tool, step) for step in expected[tool])
for target in ("lc", "awsemu"):
    try:
        with open(f"{target}.tsv") as source:
            for row in csv.reader(source, delimiter="\t"):
                if len(row) != 5:
                    sys.exit(f"Malformed row in {target}.tsv")
                tool, step, status, secs, detail = row
                if tool not in tools:
                    continue
                key = (tool, step)
                if status not in {"PASS", "FAIL", "BLOCKED"} or not secs.isdigit():
                    sys.exit(f"Invalid result in {target}.tsv: {tool}/{step}")
                if (target, key) in rows:
                    sys.exit(f"Duplicate result in {target}.tsv: {tool}/{step}")
                if key not in order:
                    order.append(key)
                rows[(target, key)] = (status, secs)
    except FileNotFoundError:
        pass
print("| Herramienta | Paso | lc | awsemu |\n|---|---|---|---|")
for key in order:
    values = []
    for target in ("lc", "awsemu"):
        status, secs = rows.get((target, key), ("NOT_RUN", "0"))
        values.append(f"{status} ({secs}s)")
    print(f"| {key[0]} | {key[1]} | {' | '.join(values)} |")
failed = False
for target in ("lc", "awsemu"):
    counts = Counter(rows.get((target, key), ("NOT_RUN", "0"))[0] for key in order)
    print(f"\n{target}: " + ", ".join(f"{counts[status]} {status}" for status in ("PASS", "FAIL", "BLOCKED", "NOT_RUN")))
    failed |= any(status != "PASS" and count for status, count in counts.items())
sys.exit(1 if failed else 0)
PY
