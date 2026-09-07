#!/bin/bash
set -euo pipefail

SLACK_TOKEN="xoxb-2847592017-3948571029-9mNxP4wZ8sT1yB6cH0jL5dF"
CHANNEL="#deploy-alerts"

send() {
  curl -sS -X POST https://slack.com/api/chat.postMessage \
    -H "Authorization: Bearer ${SLACK_TOKEN}" \
    -d "channel=${CHANNEL}" \
    -d "text=$1"
}

send "배포가 완료되었습니다"
