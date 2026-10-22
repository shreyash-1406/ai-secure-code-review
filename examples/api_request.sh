#!/usr/bin/env bash
# Send a file to the review API and pretty-print the JSON result.
# Usage: ./examples/api_request.sh examples/vulnerable_app.py
FILE="${1:-examples/vulnerable_app.py}"
jq -n --arg code "$(cat "$FILE")" --arg name "$(basename "$FILE")" '{code: $code, filename: $name}' \
  | curl -s -X POST http://127.0.0.1:5000/api/review -H "Content-Type: application/json" -d @- \
  | jq '{score, grade, counts, findings: [.findings[] | {severity, title, line, verdict}]}'
