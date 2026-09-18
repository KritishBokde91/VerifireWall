#!/usr/bin/env bash
# VeriFireWall Demo Recording - Self-contained runner
set -e

PROJ=/home/Kritish/Development/verifierwall
OUTPUT="$PROJ/verifirewall_demo.mp4"

echo "======================================================"
echo "  VeriFireWall Demo Recording - Full Setup"
echo "======================================================"

# Kill leftover processes
pkill -f verifirewall_dashboard_server 2>/dev/null || true
pkill Xvfb 2>/dev/null || true
pkill -f "google-chrome-stable" 2>/dev/null || true
sleep 2

# Ensure docker containers are running
docker start juiceshop-backend 2>/dev/null || true
docker restart appsec-nginx 2>/dev/null || true
echo "→ Waiting for nginx to settle..."
sleep 8

# Verify services
for url in "http://localhost/" "http://localhost:3000/" "http://localhost:3001/" "http://localhost:9999/"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" || echo "000")
    echo "  $url → $code"
done

# Start dashboard server
echo "→ Starting VeriFireWall dashboard server..."
cd "$PROJ"
/usr/bin/python3 examples/verifirewall_dashboard_server.py &> /tmp/vfw_dashboard.log &
DASH_PID=$!
sleep 4

# Verify dashboard
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:3002/ || echo "000")
echo "  http://localhost:3002/ → $code"
if [ "$code" != "200" ]; then
    echo "ERROR: Dashboard server not responding!"
    cat /tmp/vfw_dashboard.log
    exit 1
fi

echo "✓ All services ready"
echo "→ Running recording script..."

/usr/bin/python3 "$PROJ/examples/make_demo_recording.py"
EXIT_CODE=$?

kill $DASH_PID 2>/dev/null || true

if [ $EXIT_CODE -eq 0 ] && [ -f "$OUTPUT" ]; then
    SIZE=$(du -sh "$OUTPUT" | cut -f1)
    DURATION=$(ffprobe -v quiet -print_format json -show_format "$OUTPUT" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(round(float(d['format']['duration']),1),'sec')" 2>/dev/null || echo "?")
    echo ""
    echo "======================================================"
    echo "  🎉 Recording complete!"
    echo "  📹  $OUTPUT"
    echo "  📦  Size: $SIZE"
    echo "  ⏱️   Duration: $DURATION"
    echo "======================================================"
else
    echo "Recording failed! Exit code: $EXIT_CODE"
    exit 1
fi
