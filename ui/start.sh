#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Agentic Web Pentest — UI  |  start.sh
#  Builds and starts the Docker stack (backend + frontend).
#  Usage:
#    ./start.sh            # normal start (incremental build)
#    ./start.sh --rebuild  # force full image rebuild (--no-cache)
#    ./start.sh --logs     # start and follow logs immediately
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
BOLD='\033[1m'; CYAN='\033[96m'; GREEN='\033[92m'
YELLOW='\033[93m'; RED='\033[91m'; DIM='\033[2m'; RST='\033[0m'

info()    { echo -e "${CYAN}  ◈  ${RST}${BOLD}$*${RST}"; }
success() { echo -e "${GREEN}  ✔  ${RST}$*"; }
warn()    { echo -e "${YELLOW}  ⚠  ${RST}$*"; }
error()   { echo -e "${RED}  ✘  ${RST}${BOLD}$*${RST}"; }
sep()     { echo -e "${DIM}$(printf '─%.0s' {1..72})${RST}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}  Agentic Web Pentest  —  Web UI${RST}  ${DIM}v0.5.0${RST}"
echo -e "${DIM}  Enterprise-Grade Autonomous Penetration Testing Platform${RST}"
sep

# ── Parse flags ───────────────────────────────────────────────────────────────
REBUILD=false
FOLLOW_LOGS=false
for arg in "$@"; do
  case "$arg" in
    --rebuild) REBUILD=true ;;
    --logs)    FOLLOW_LOGS=true ;;
    -h|--help)
      echo ""
      echo "  Usage: ./start.sh [OPTIONS]"
      echo ""
      echo "  Options:"
      echo "    --rebuild   Force full image rebuild (docker compose build --no-cache)"
      echo "    --logs      Follow container logs after startup"
      echo "    --help      Show this help"
      echo ""
      exit 0 ;;
    *)
      error "Unknown option: $arg"
      echo "  Run './start.sh --help' for usage."
      exit 1 ;;
  esac
done

# ── Locate docker-compose.yml ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

if [[ ! -f "$COMPOSE_FILE" ]]; then
  error "docker-compose.yml not found at: $COMPOSE_FILE"
  exit 1
fi

# ── Check .env (optional but recommended) ────────────────────────────────────
ENV_FILE="$SCRIPT_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  warn ".env file not found — using defaults from docker-compose.yml"
  warn "Copy .env.example → .env and set SECRET_KEY / ENCRYPTION_KEY before production use"
fi

# ── Check Docker is available and running ─────────────────────────────────────
if ! command -v docker &>/dev/null; then
  error "Docker is not installed or not in PATH."
  exit 1
fi
if ! docker info &>/dev/null; then
  error "Docker daemon is not running. Start it with: sudo systemctl start docker"
  exit 1
fi

# ── Build images ──────────────────────────────────────────────────────────────
echo ""
if $REBUILD; then
  info "Building images (--no-cache) …"
  docker compose -f "$COMPOSE_FILE" build --no-cache
else
  info "Building images (incremental) …"
  docker compose -f "$COMPOSE_FILE" build
fi

# ── Start containers ──────────────────────────────────────────────────────────
echo ""
info "Starting containers …"
docker compose -f "$COMPOSE_FILE" up -d

# ── Health check — wait for backend ──────────────────────────────────────────
echo ""
info "Waiting for backend to become healthy …"
BACKEND_URL="http://localhost:8000/health"
MAX_WAIT=60
WAITED=0
until curl -sf "$BACKEND_URL" &>/dev/null; do
  if [[ $WAITED -ge $MAX_WAIT ]]; then
    warn "Backend did not respond within ${MAX_WAIT}s — check logs with: ./start.sh --logs"
    break
  fi
  printf "${DIM}  .${RST}"
  sleep 2
  WAITED=$((WAITED + 2))
done
echo ""

# ── Status summary ────────────────────────────────────────────────────────────
sep
echo ""
success "Stack is up and running"
echo ""
echo -e "  ${BOLD}Frontend${RST}   ${CYAN}http://localhost:3000${RST}"
echo -e "  ${BOLD}Backend${RST}    ${CYAN}http://localhost:8000${RST}"
echo -e "  ${BOLD}API Docs${RST}   ${CYAN}http://localhost:8000/docs${RST}"
echo ""
echo -e "  ${DIM}Default credentials:${RST}"
echo -e "  ${DIM}  Username  admin${RST}"
echo -e "  ${DIM}  Password  changeme123  (set ADMIN_PASSWORD in .env)${RST}"
echo ""
sep
echo ""
echo -e "  ${DIM}Useful commands:${RST}"
echo -e "  ${DIM}  ./stop.sh              — Stop all containers${RST}"
echo -e "  ${DIM}  ./start.sh --rebuild   — Force full image rebuild${RST}"
echo -e "  ${DIM}  docker compose logs -f — Follow live logs${RST}"
echo ""

# ── Follow logs if requested ──────────────────────────────────────────────────
if $FOLLOW_LOGS; then
  echo -e "${DIM}  Following logs (Ctrl+C to exit) …${RST}"
  echo ""
  docker compose -f "$COMPOSE_FILE" logs -f
fi
