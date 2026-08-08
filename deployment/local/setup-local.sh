#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# open-appsec Local Stack — One-Command Setup
# Usage: ./setup-local.sh [up|down|restart|logs|test|status]
# ──────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.local.yaml"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "  ╔══════════════════════════════════════════════════╗"
  echo "  ║      open-appsec — Local WAF Stack               ║"
  echo "  ║      100% Local · No Cloud · No Accounts         ║"
  echo "  ╚══════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

create_dirs() {
  echo -e "${YELLOW}→ Creating required directories...${NC}"
  mkdir -p \
    "$SCRIPT_DIR/appsec-config" \
    "$SCRIPT_DIR/appsec-data" \
    "$SCRIPT_DIR/appsec-logs" \
    "$SCRIPT_DIR/appsec-smartsync-storage" \
    "$SCRIPT_DIR/appsec-postgres-data" \
    "$SCRIPT_DIR/nginx-config" \
    "$SCRIPT_DIR/appsec-localconfig" \
    "$SCRIPT_DIR/prometheus" \
    "$SCRIPT_DIR/grafana/provisioning/datasources" \
    "$SCRIPT_DIR/grafana/provisioning/dashboards"
  echo -e "${GREEN}✓ Directories ready${NC}"
}

start_stack() {
  banner
  create_dirs
  echo -e "${YELLOW}→ Pulling latest Docker images...${NC}"
  docker compose -f "$COMPOSE_FILE" pull --quiet
  echo -e "${YELLOW}→ Starting all services...${NC}"
  docker compose -f "$COMPOSE_FILE" up -d
  echo ""
  echo -e "${GREEN}${BOLD}✅ Stack is up! Access your services:${NC}"
  echo ""
  echo -e "  🛡️  ${BOLD}Protected App (WAF + JuiceShop)${NC}  → ${CYAN}http://localhost${NC}"
  echo -e "  📊  ${BOLD}Grafana Dashboard${NC}                 → ${CYAN}http://localhost:3001${NC}  (admin / appsec123)"
  echo -e "  📈  ${BOLD}Prometheus Metrics${NC}                → ${CYAN}http://localhost:9090${NC}"
  echo -e "  📋  ${BOLD}Live Container Logs (Dozzle)${NC}      → ${CYAN}http://localhost:9999${NC}"
  echo -e "  🍹  ${BOLD}JuiceShop (direct, no WAF)${NC}       → ${CYAN}http://localhost:3000${NC}"
  echo ""
  echo -e "  ${YELLOW}Tip: Run ${BOLD}./setup-local.sh test${NC}${YELLOW} to fire attack simulations!${NC}"
  echo ""
}

stop_stack() {
  echo -e "${YELLOW}→ Stopping all services...${NC}"
  docker compose -f "$COMPOSE_FILE" down
  echo -e "${GREEN}✓ Stack stopped${NC}"
}

show_status() {
  echo -e "${BOLD}Container Status:${NC}"
  docker compose -f "$COMPOSE_FILE" ps
}

show_logs() {
  SERVICE=${2:-appsec-agent}
  echo -e "${YELLOW}→ Streaming logs for: ${BOLD}$SERVICE${NC}"
  docker compose -f "$COMPOSE_FILE" logs -f "$SERVICE"
}

run_attack_tests() {
  echo -e "${CYAN}${BOLD}"
  echo "  ══════════════════════════════════════════"
  echo "   🔥 open-appsec Attack Simulation Tests"
  echo "  ══════════════════════════════════════════"
  echo -e "${NC}"
  TARGET="http://localhost"
  PASS=0; FAIL=0

  run_test() {
    local name="$1"; local url="$2"; local expected_code="$3"; local payload="$4"
    local actual
    if [ -n "$payload" ]; then
      actual=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        --data "$payload" \
        --max-time 5 "$url" 2>/dev/null || echo "000")
    else
      actual=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 5 "$url" 2>/dev/null || echo "000")
    fi
    if [ "$actual" = "$expected_code" ]; then
      echo -e "  ${GREEN}✓ PASS${NC}  $name  [got $actual]"
      PASS=$((PASS+1))
    else
      echo -e "  ${RED}✗ FAIL${NC}  $name  [expected $expected_code, got $actual]"
      FAIL=$((FAIL+1))
    fi
  }

  echo -e "\n${BOLD}── Normal Traffic (expect 200) ──${NC}"
  run_test "Homepage"                    "$TARGET/"                                        "200"
  run_test "REST API endpoint"           "$TARGET/api/Products"                            "200"

  echo -e "\n${BOLD}── SQL Injection (expect 403 — WAF blocks) ──${NC}"
  run_test "SQLi basic OR"               "$TARGET/?id=1'+OR+'1'='1"                        "403"
  run_test "SQLi UNION"                  "$TARGET/?q=1+UNION+SELECT+null,null,null--"      "403"
  run_test "SQLi comment bypass"         "$TARGET/?user=admin'--"                          "403"
  run_test "SQLi in body"                "$TARGET/api/Users" "403" '{"email":"a@a.com OR 1=1--","password":"x"}'

  echo -e "\n${BOLD}── Cross-Site Scripting XSS (expect 403) ──${NC}"
  run_test "XSS script tag"              "$TARGET/?q=<script>alert(1)</script>"            "403"
  run_test "XSS img onerror"            "$TARGET/?search=<img+src=x+onerror=alert(1)>"    "403"
  run_test "XSS javascript URI"          "$TARGET/?url=javascript:alert(document.cookie)"  "403"

  echo -e "\n${BOLD}── Path Traversal (expect 403) ──${NC}"
  run_test "Path traversal /etc/passwd"  "$TARGET/?file=../../etc/passwd"                  "403"
  run_test "Path traversal ../"          "$TARGET/../../../etc/shadow"                      "403"

  echo -e "\n${BOLD}── Command Injection (expect 403) ──${NC}"
  run_test "CMD injection semicolon"     "$TARGET/?cmd=;cat+/etc/passwd"                   "403"
  run_test "CMD injection pipe"          "$TARGET/?q=|whoami"                              "403"

  echo -e "\n${BOLD}── Results ──${NC}"
  echo -e "  ${GREEN}Passed: $PASS${NC}  |  ${RED}Failed: $FAIL${NC}"
  echo ""
  if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}🎉 All tests passed! WAF is working correctly.${NC}"
  else
    echo -e "  ${YELLOW}⚠️  Some tests failed. Check agent logs:${NC}"
    echo -e "  ${CYAN}./setup-local.sh logs appsec-agent${NC}"
  fi
  echo ""
}

watch_logs() {
  echo -e "${YELLOW}→ Watching open-appsec security logs (JSON formatted)...${NC}"
  echo -e "${YELLOW}  (Press Ctrl+C to stop)${NC}\n"
  docker compose -f "$COMPOSE_FILE" logs -f appsec-agent | \
    grep --line-buffered -i "block\|prevent\|detect\|threat\|attack\|403\|waap" | \
    while IFS= read -r line; do
      echo -e "${RED}🚨 ${line}${NC}"
    done
}

# ── Main ──────────────────────────────────────────────────────────────────────
CMD=${1:-up}
case "$CMD" in
  up|start)       start_stack ;;
  down|stop)      stop_stack ;;
  restart)        stop_stack; sleep 2; start_stack ;;
  status|ps)      show_status ;;
  logs)           show_logs "$@" ;;
  test|attack)    run_attack_tests ;;
  watch)          watch_logs ;;
  *)
    echo -e "${BOLD}Usage:${NC} $0 [command]"
    echo ""
    echo "  ${CYAN}up${NC}       Start the entire local stack"
    echo "  ${CYAN}down${NC}     Stop all containers"
    echo "  ${CYAN}restart${NC}  Restart everything"
    echo "  ${CYAN}status${NC}   Show container status"
    echo "  ${CYAN}logs${NC}     Stream logs (default: appsec-agent)"
    echo "  ${CYAN}test${NC}     Run attack simulation tests"
    echo "  ${CYAN}watch${NC}    Watch security events in real-time"
    ;;
esac
