#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  VIGILOR UI  |  stop.sh
#  Stops the Docker stack and optionally removes data volumes.
#  Usage:
#    ./stop.sh              # graceful stop (containers only)
#    ./stop.sh --clean      # stop + remove containers and images
#    ./stop.sh --purge      # stop + remove everything incl. data volumes (⚠ destructive)
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
echo -e "${BOLD}${CYAN}  VIGILOR Web UI${RST}  ${DIM}v1.0.0${RST}"
echo -e "${DIM}  Autonomous Web VAPT${RST}"
sep

# ── Parse flags ───────────────────────────────────────────────────────────────
CLEAN=false
PURGE=false
for arg in "$@"; do
  case "$arg" in
    --clean) CLEAN=true ;;
    --purge) PURGE=true ;;
    -h|--help)
      echo ""
      echo "  Usage: ./stop.sh [OPTIONS]"
      echo ""
      echo "  Options:"
      echo "    --clean   Stop containers and remove images (frees disk space)"
      echo "    --purge   Stop + remove containers, images, AND data volumes"
      echo "              ⚠  ALL scan data, findings, and reports will be deleted"
      echo "    --help    Show this help"
      echo ""
      exit 0 ;;
    *)
      error "Unknown option: $arg"
      echo "  Run './stop.sh --help' for usage."
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

# ── Check Docker is available ─────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  error "Docker is not installed or not in PATH."
  exit 1
fi

# ── Purge warning ─────────────────────────────────────────────────────────────
if $PURGE; then
  echo ""
  warn "You are about to run --purge."
  warn "This will permanently delete the 'pentest_data' volume."
  warn "All scan data, findings, reports, and the database will be lost."
  echo ""
  read -rp "  Type 'yes' to confirm: " CONFIRM
  if [[ "$CONFIRM" != "yes" ]]; then
    echo ""
    echo -e "  ${DIM}Aborted — no changes made.${RST}"
    echo ""
    exit 0
  fi
fi

# ── Stop + remove (single compose down call handles everything cleanly) ──────
echo ""
if $PURGE; then
  info "Stopping and removing containers, images, and volumes …"
  docker compose -f "$COMPOSE_FILE" down --rmi local -v --remove-orphans || true
elif $CLEAN; then
  info "Stopping and removing containers and images …"
  docker compose -f "$COMPOSE_FILE" down --rmi local --remove-orphans || true
else
  info "Stopping containers …"
  docker compose -f "$COMPOSE_FILE" stop
fi

# ── Status summary ────────────────────────────────────────────────────────────
echo ""
sep
echo ""

if $PURGE; then
  success "Stack fully purged — containers, images, and volumes removed"
elif $CLEAN; then
  success "Stack stopped — containers and images removed"
else
  success "Stack stopped — containers preserved (data intact)"
fi

echo ""

if ! $PURGE; then
  echo -e "  ${DIM}To restart:     ./start.sh${RST}"
fi
if ! $CLEAN && ! $PURGE; then
  echo -e "  ${DIM}To clean up:    ./stop.sh --clean${RST}"
fi
echo -e "  ${DIM}To purge all:   ./stop.sh --purge   ${YELLOW}⚠ deletes all data${RST}"
echo ""
sep
echo ""
