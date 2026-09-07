#!/bin/bash
set -euo pipefail

HEROKU_API_KEY=9f86d081-884c-7d65-9a2f-eaa0c55ad015
APP_NAME=my-app-prod

heroku container:push web --app "$APP_NAME"
heroku container:release web --app "$APP_NAME"
