#!/bin/bash
# Start API and Dashboard in background (for Codespaces postStartCommand)
cd "$(dirname "$0")/.." || exit 1
make api > /tmp/nullvoid-api.log 2>&1 &
sleep 5
make dashboard > /tmp/nullvoid-dashboard.log 2>&1 &
echo "API (3001) and Dashboard (5174) starting in background. Check Ports panel."
