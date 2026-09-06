#!/usr/bin/env bash
# ======================================================================
# wsl2_attack_stand.sh — подъём стенда безопасности и запуск red-team
# атак (mcp_attack) под Windows / WSL 2.
#
# Разбирается с тем, что в WSL 2 обычно ломается по сравнению с Linux/macOS:
#   * контейнеры не видят Ollama (host.docker.internal / host-gateway);
#   * различие Docker Desktop и нативного dockerd внутри дистрибутива;
#   * отсутствующий самоподписанный TLS-сертификат Keycloak;
#   * отсутствующий .env.
#
# Скрипт идемпотентный: ничего не перезаписывает молча (.env создаётся
# только если его нет), override для Ollama — аддитивный и в .gitignore.
#
# Использование:
#   scripts/wsl2_attack_stand.sh check     # префлайт окружения
#   scripts/wsl2_attack_stand.sh smoke     # офлайн-проверка движка атак (без Docker)
#   scripts/wsl2_attack_stand.sh certs     # сгенерировать TLS-сертификат Keycloak
#   scripts/wsl2_attack_stand.sh env       # создать .env и настроить доставку к Ollama
#   scripts/wsl2_attack_stand.sh up        # поднять стенд и дождаться healthy
#   scripts/wsl2_attack_stand.sh ps        # статус сервисов
#   scripts/wsl2_attack_stand.sh down      # остановить стенд
#   scripts/wsl2_attack_stand.sh attack [--url URL] [--model M] [-- extra mcp_attack args]
#   scripts/wsl2_attack_stand.sh setup     # check -> certs -> env (без up)
#
# Полный разбор — docs/wsl2_attack_testing.md
# ======================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ---- логирование -----------------------------------------------------
if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[34m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_OFF=""
fi
ok()   { printf '%s[ OK ]%s %s\n'   "$C_GRN" "$C_OFF" "$*"; }
warn() { printf '%s[WARN]%s %s\n'   "$C_YEL" "$C_OFF" "$*"; }
err()  { printf '%s[FAIL]%s %s\n'   "$C_RED" "$C_OFF" "$*" >&2; }
info() { printf '%s[ .. ]%s %s\n'   "$C_BLU" "$C_OFF" "$*"; }
hdr() { printf '\n%s== %s ==%s\n'  "$C_BLU" "$*" "$C_OFF"; }

OLLAMA_PORT="${OLLAMA_PORT:-11434}"

# ---- обнаружение окружения ------------------------------------------
is_wsl() { grep -qiE '(microsoft|wsl)' /proc/version 2>/dev/null; }

docker_daemon_up() { docker info >/dev/null 2>&1; }

# "Docker Desktop" -> desktop; иначе нативный dockerd в дистрибутиве.
docker_flavor() {
  local osname
  osname="$(docker info --format '{{.OperatingSystem}}' 2>/dev/null || true)"
  case "$osname" in
    *"Docker Desktop"*) echo "desktop" ;;
    "")                 echo "unknown" ;;
    *)                  echo "native"  ;;
  esac
}

# IP Windows-хоста, каким его видит WSL 2 (шлюз по умолчанию, затем resolv.conf).
windows_host_ip() {
  local ip
  ip="$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')"
  [ -z "$ip" ] && ip="$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"
  echo "$ip"
}

probe_ollama() { # $1 = host
  curl -fsS -m 3 "http://$1:${OLLAMA_PORT}/api/tags" >/dev/null 2>&1
}

compose() { docker compose "$@"; }

need_realm() {
  if [ ! -f keycloak/realm-export.json ]; then
    err "keycloak/realm-export.json не найден — realm genai-stand, клиенты и"
    err "пользователи client1001..1005 не будут импортированы, стенд не"
    err "аутентифицирует запросы. Этот файл не закоммичен в репозиторий."
    err "См. docs/wsl2_attack_testing.md, раздел «Полный стенд»."
    return 1
  fi
  return 0
}

# ---- команды ---------------------------------------------------------
cmd_check() {
  hdr "Префлайт окружения"
  if is_wsl; then ok "WSL 2: $(sed -n 's/.*\( WSL[0-9]*\).*/\1/p;q' /proc/version 2>/dev/null; uname -r)"
  else warn "не похоже на WSL 2 (это нормально для Linux/CI, но скрипт заточен под WSL 2)"; fi

  if command -v docker >/dev/null 2>&1; then ok "docker: $(docker --version)"
  else err "docker не найден в PATH (Docker Desktop: включите WSL integration для дистрибутива)"; fi

  if compose version >/dev/null 2>&1; then ok "docker compose: $(compose version --short 2>/dev/null || compose version | head -1)"
  else err "плагин 'docker compose' не найден (нужен v2, не docker-compose)"; fi

  if docker_daemon_up; then
    ok "docker daemon отвечает (flavor: $(docker_flavor))"
  else
    err "docker daemon недоступен. Docker Desktop: запустите Desktop и включите"
    err "  Settings -> Resources -> WSL integration для этого дистрибутива."
    err "  Нативный dockerd: sudo service docker start (или запустите dockerd)."
  fi

  command -v python3 >/dev/null 2>&1 && ok "python3: $(python3 --version 2>&1)" || err "python3 не найден"
  command -v openssl >/dev/null 2>&1 && ok "openssl доступен" || warn "openssl не найден — команда certs не сработает"

  [ -f .env ] && ok ".env есть" || warn ".env нет — создайте: $0 env"
  [ -f keycloak/certs/tls.crt ] && ok "TLS-сертификат Keycloak есть" || warn "TLS-сертификата нет — $0 certs"
  if [ -f keycloak/realm-export.json ]; then ok "keycloak/realm-export.json есть"
  else warn "keycloak/realm-export.json НЕТ — путь «полный стенд» заблокирован (см. docs/wsl2_attack_testing.md)"; fi

  hdr "Доступность Ollama (для контейнеров нужен 0.0.0.0, не 127.0.0.1)"
  local win_ip; win_ip="$(windows_host_ip)"
  if probe_ollama localhost; then ok "Ollama отвечает на localhost:${OLLAMA_PORT} (WSL-локально или проброс/mirrored)"
  else info "на localhost:${OLLAMA_PORT} Ollama не отвечает"; fi
  if [ -n "$win_ip" ] && probe_ollama "$win_ip"; then ok "Ollama отвечает на Windows-хосте ${win_ip}:${OLLAMA_PORT}"
  else [ -n "$win_ip" ] && info "на Windows-хосте ${win_ip}:${OLLAMA_PORT} Ollama не отвечает" || true; fi
}

cmd_certs() {
  hdr "TLS-сертификат Keycloak"
  mkdir -p keycloak/certs
  if [ -f keycloak/certs/tls.crt ] && [ -f keycloak/certs/tls.key ]; then
    ok "сертификат уже есть — пропускаю (удалите keycloak/certs/tls.* для перегенерации)"; return 0
  fi
  command -v openssl >/dev/null 2>&1 || { err "нужен openssl"; return 1; }
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout keycloak/certs/tls.key -out keycloak/certs/tls.crt -days 3650 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:keycloak,IP:127.0.0.1"
  ok "сгенерирован keycloak/certs/{tls.crt,tls.key} (в .gitignore)"
}

cmd_env() {
  hdr "Конфигурация .env и доставка к Ollama"
  if [ ! -f .env ]; then
    [ -f .env.example ] || { err ".env.example отсутствует"; return 1; }
    cp .env.example .env
    ok "создан .env из .env.example"
  else
    ok ".env уже есть — не трогаю (правьте вручную)"
  fi

  local flavor; flavor="$(docker_flavor)"
  local win_ip; win_ip="$(windows_host_ip)"
  info "docker flavor: ${flavor}; Windows-хост из WSL: ${win_ip:-неизвестен}"

  # Нативный dockerd: host.docker.internal НЕ определён по умолчанию —
  # добавляем его на agent-api через host-gateway аддитивным override.
  if [ "$flavor" = "native" ]; then
    if [ ! -f docker-compose.override.yml ]; then
      cat > docker-compose.override.yml <<'YAML'
# Сгенерировано scripts/wsl2_attack_stand.sh для нативного dockerd в WSL 2.
# host.docker.internal там не определён по умолчанию — маппим его на
# WSL2-хост (host-gateway), где слушает Ollama (0.0.0.0). В .gitignore.
services:
  agent-api:
    extra_hosts:
      - "host.docker.internal:host-gateway"
YAML
      ok "создан docker-compose.override.yml (host.docker.internal -> host-gateway для agent-api)"
    else
      ok "docker-compose.override.yml уже есть — не трогаю"
    fi
    info "Ollama должна слушать 0.0.0.0 внутри WSL 2: OLLAMA_HOST=0.0.0.0 ollama serve"
  elif [ "$flavor" = "desktop" ]; then
    info "Docker Desktop: host.docker.internal уже указывает на Windows-хост."
    info "Запускайте Ollama на Windows с OLLAMA_HOST=0.0.0.0 — тогда дефолтный"
    info "OPENAI_BASE_URL=http://host.docker.internal:${OLLAMA_PORT}/v1 сработает."
  fi

  # Диагностика достижимости + подсказка значения OPENAI_BASE_URL.
  if probe_ollama localhost; then
    ok "Ollama отвечает на localhost:${OLLAMA_PORT}"
    if [ "$flavor" = "desktop" ]; then
      warn "Docker Desktop + Ollama только в WSL: контейнеры НЕ увидят её через"
      warn "  host.docker.internal (он указывает на Windows). Варианты: перенести"
      warn "  Ollama на Windows (0.0.0.0), либо использовать OpenRouter (см. .env)."
    fi
  elif [ -n "$win_ip" ] && probe_ollama "$win_ip"; then
    ok "Ollama отвечает на Windows-хосте ${win_ip}:${OLLAMA_PORT}"
  else
    warn "Ollama сейчас недоступна ни на localhost, ни на Windows-хосте."
    warn "  Проверьте, что она запущена и слушает 0.0.0.0 (не 127.0.0.1)."
    warn "  Либо переключитесь на OpenRouter/иного провайдера в .env."
  fi
  info "Текущее OPENAI_BASE_URL в .env:"
  grep -E '^OPENAI_BASE_URL=' .env || true
}

cmd_up() {
  hdr "Подъём стенда"
  docker_daemon_up || { err "docker daemon недоступен (см. $0 check)"; return 1; }
  need_realm || return 1
  [ -f keycloak/certs/tls.crt ] || { warn "нет TLS-сертификата — генерирую"; cmd_certs; }
  [ -f .env ] || cmd_env
  info "docker compose up -d --build (первый прогон Keycloak с импортом realm ~20-40с)"
  compose up -d --build
  hdr "Ожидание healthy"
  # Ждём сервисы с healthcheck (redis/mongo/postgres/keycloak/invest-server).
  # Разбираем .Status по подстроке "(healthy)" — портируемее, чем {{.Health}}.
  local deadline=$(( $(date +%s) + 180 )) line all_ok
  while :; do
    all_ok=1
    while IFS= read -r line; do
      case "$line" in redis*|mongo*|postgres*|keycloak*|invest-server*) ;; *) continue ;; esac
      case "$line" in *"(healthy)"*) ;; *) all_ok=0 ;; esac
    done < <(compose ps --format '{{.Service}} {{.Status}}' 2>/dev/null)
    [ "$all_ok" = 1 ] && { ok "ключевые сервисы healthy"; break; }
    [ "$(date +%s)" -ge "$deadline" ] && { warn "таймаут ожидания healthy — см. $0 ps и логи"; break; }
    sleep 4
  done
  cmd_ps
  hdr "Дальше"
  cat <<TXT
  Точки входа (браузер на Windows, WSL пробрасывает localhost):
    LibreChat        : http://localhost:3080   (Continue with OpenID -> client1001..1005 / пароль=логин)
    Мой аккаунт/ключи: http://localhost:8501   (страница выдаёт API-ключи sk-genai-...)
    agent-api        : http://localhost:8600   (Authorization: Bearer sk-genai-...)
  Возьмите ДВА ключа (атакующий + жертва) на странице аккаунта, затем:
    $0 attack --url http://localhost:8600/v1 --model genai-invest-agent
  Полный разбор запуска атак — docs/wsl2_attack_testing.md
TXT
}

cmd_ps()   { hdr "Статус"; compose ps 2>/dev/null || true; }
cmd_down() { hdr "Остановка"; compose down; ok "остановлено"; }

cmd_smoke() {
  hdr "Офлайн-проверка движка атак (Docker не нужен)"
  export PYTHONPATH="${PYTHONPATH:-}:$REPO_ROOT"
  info "валидация каталога (--strict-taxonomy)"
  python3 -m mcp_attack validate-catalog mcp_attack/catalog/prompts --strict-taxonomy | tail -1
  info "инвентарь вариантов (invest_bank overlay)"
  python3 -m mcp_attack list-catalog --catalog mcp_attack/catalog/prompts/domain/invest_bank 2>/dev/null | tail -1
  info "офлайн pytest (подмножество атак)"
  python3 -m pytest -q \
    tests/test_attack_catalog_loader.py \
    tests/test_attack_taxonomy.py \
    tests/test_attack_catalog_taxonomy_strict.py \
    tests/test_attack_config.py 2>&1 | tail -1
  ok "движок атак работоспособен в этом окружении"
}

cmd_attack() {
  local url="http://localhost:8600/v1" model="genai-invest-agent" passthru=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --url)   url="$2"; shift 2 ;;
      --model) model="$2"; shift 2 ;;
      --)      shift; passthru=("$@"); break ;;
      *)       passthru+=("$1"); shift ;;
    esac
  done
  hdr "Атака: mcp_attack quickstart -> ${url} (${model})"
  export PYTHONPATH="${PYTHONPATH:-}:$REPO_ROOT"
  if ! curl -fsS -m 3 "${url%/v1}/v1/models" >/dev/null 2>&1 && ! curl -fsS -m 3 "$url" >/dev/null 2>&1; then
    warn "цель ${url} не отвечает — поднят ли стенд ($0 up)?"
  fi
  info "маркеры-канарейки увидите в .attack/run.md; HTML-отчёт в .attack/run.html"
  set -x
  python3 -m mcp_attack quickstart --url "$url" --model "$model" \
    --out .attack --report-html .attack/run.html "${passthru[@]}"
}

cmd_setup() { cmd_check; cmd_certs; cmd_env; hdr "Готово к $0 up"; }

usage() { sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

case "${1:-help}" in
  check)  cmd_check ;;
  smoke)  cmd_smoke ;;
  certs)  cmd_certs ;;
  env)    cmd_env ;;
  up)     cmd_up ;;
  ps)     cmd_ps ;;
  down)   cmd_down ;;
  attack) shift; cmd_attack "$@" ;;
  setup)  cmd_setup ;;
  help|-h|--help) usage ;;
  *) err "неизвестная команда: $1"; echo; usage; exit 2 ;;
esac
