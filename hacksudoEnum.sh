#!/usr/bin/env bash
# subhs1.sh - Subdomain enumeration (crt.sh + wordlist brute) with safe tool fallbacks,
#             colored banner + friendly output.
# Usage: ./subhs1.sh domain wordlist.txt
set -euo pipefail
IFS=$'\n\t'

# --------- Config ----------
DOMAIN="${1:-}"
WORDLIST="${2:-}"
OUTDIR="results"
TMPDIR="$(mktemp -d -t subhs1.XXXXXX)"
PARALLEL=50
PASSIVE_ONLY=false
PROBE_HTTP=true

# --------- ANSI Colors ----------
CLR_RESET="\033[0m"
CLR_RED="\033[31m"
CLR_GREEN="\033[32m"
CLR_YELLOW="\033[33m"
CLR_BLUE="\033[34m"
CLR_CYAN="\033[36m"
CLR_BOLD="\033[1m"

# --------- Helpers ----------
log(){ printf '%s %b%s%b\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$CLR_CYAN" "$*" "$CLR_RESET"; }
info(){ printf '%b%s%b\n' "$CLR_GREEN" "$*" "$CLR_RESET"; }
warn(){ printf '%b%s%b\n' "$CLR_YELLOW" "$*" "$CLR_RESET"; }
err(){ printf '%b%s%b\n' "$CLR_RED" "$*" "$CLR_RESET"; }

cleanup(){ rm -rf "$TMPDIR"; }
trap cleanup EXIT

# --------- Banner ----------
show_banner(){
  echo -e "${CLR_BOLD}${CLR_BLUE}"
  echo "=============================================="
  echo "   Hacksudo Subdomain Enumerator"
  echo "   - crt.sh scraping"
  echo "   - wordlist brute-force (uses dnsx/dig fallback)"
  echo "   - safe permutations"
  echo "   - resolves hosts (dnsx/massdns/dig)"
  echo "   - optional HTTP probe (httpx/curl)"
  echo "=============================================="
  echo -e "${CLR_RESET}"
}

# --------- Validate args ----------
if [ -z "$DOMAIN" ] || [ -z "$WORDLIST" ]; then
  show_banner
  echo -e "${CLR_BOLD}Usage:${CLR_RESET} $0 domain wordlist.txt"
  exit 1
fi

if [ ! -f "$WORDLIST" ]; then
  err "Wordlist not found: $WORDLIST"
  exit 1
fi

mkdir -p "$OUTDIR"

CRT_OUT="$OUTDIR/${DOMAIN}_crt.txt"
BRUTE_OUT="$OUTDIR/${DOMAIN}_bruteforce.txt"
ALL_OUT="$OUTDIR/${DOMAIN}_all.txt"
RES_OUT="$OUTDIR/${DOMAIN}_resolved.txt"
HTTP_OUT="$OUTDIR/${DOMAIN}_live.txt"

# ensure files exist (so later wc -l or reads don't fail)
: > "$CRT_OUT"
: > "$BRUTE_OUT"
: > "$ALL_OUT"
: > "$RES_OUT"

show_banner
log "Target domain: $DOMAIN"
log "Wordlist: $WORDLIST"
log "Output directory: $OUTDIR"

# --------- Prepare wordlist ----------
grep -vE '^\s*(#|$)' "$WORDLIST" | tr -d '\r' | sort -u > "$TMPDIR/wordlist.txt"
log "Wordlist size: $(wc -l < "$TMPDIR/wordlist.txt")"

# --------- Passive: crt.sh ----------
log "Querying crt.sh for certificates (passive)..."
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" \
  | tr '{}' '\n' \
  | grep -oP '"name_value"\s*:\s*"\K[^"]+' 2>/dev/null \
  | sed 's/\*\.//g' \
  | sed '/^\s*$/d' \
  | sort -u > "$CRT_OUT" || true
log "crt.sh -> $( [ -f "$CRT_OUT" ] && wc -l < "$CRT_OUT" || echo 0 ) entries"

# --------- Brute Force (wordlist -> sub.domain) ----------
if ! $PASSIVE_ONLY; then
  CAND="$TMPDIR/candidates.txt"
  awk -v d="$DOMAIN" '{ print $0 "." d }' "$TMPDIR/wordlist.txt" > "$CAND"
  log "Brute-forcing $(wc -l < "$CAND") candidates (parallel=$PARALLEL)..."

  # Prefer dnsx if available; fallback to dig parallel
  if command -v dnsx >/dev/null 2>&1; then
    # Use minimal flags to avoid incompatible option errors and capture output to temp file
    TMPBRUTE="$TMPDIR/dnsx_brute.txt"
    if dnsx -h >/dev/null 2>&1 2>/dev/null; then
      # try using -a (show A records) and -resp, but keep call simple
      set +e
      dnsx -a -silent -r 1 < "$CAND" > "$TMPBRUTE" 2>/dev/null
      rc=$?
      set -e
      if [ $rc -ne 0 ] || [ ! -s "$TMPBRUTE" ]; then
        # fallback to simpler dnsx invocation without -silent (some versions)
        dnsx -a < "$CAND" > "$TMPBRUTE" 2>/dev/null || true
      fi
    else
      # basic attempt
      dnsx -a < "$CAND" > "$TMPBRUTE" 2>/dev/null || true
    fi
    # dnsx outputs "host ip" or just host; normalize
    awk '{print $1}' "$TMPBRUTE" | sort -u > "$BRUTE_OUT" || true
  else
    # fallback to dig + xargs
    if command -v xargs >/dev/null 2>&1; then
      cat "$CAND" | xargs -n1 -P "$PARALLEL" -I{} bash -c 'dig +short "{}" | grep -q . && echo "{}"' 2>/dev/null > "$BRUTE_OUT" || true
    else
      # sequential
      while read -r h; do dig +short "$h" | grep -q . && echo "$h"; done < "$CAND" > "$BRUTE_OUT" || true
    fi
  fi

  sort -u "$BRUTE_OUT" -o "$BRUTE_OUT" || true
  log "Brute -> $( [ -f "$BRUTE_OUT" ] && wc -l < "$BRUTE_OUT" || echo 0 ) entries"
else
  log "PASSIVE_ONLY enabled — skipping brute force"
fi

# --------- Combine results ----------
cat "$CRT_OUT" "$BRUTE_OUT" 2>/dev/null | sed 's/\*\.//g' | sed '/^\s*$/d' | sort -u > "$ALL_OUT" || true
log "Combined -> $( [ -f "$ALL_OUT" ] && wc -l < "$ALL_OUT" || echo 0 ) entries"

# --------- Safe Permutations (no awk substr math) ----------
log "Adding safe permutations (www-, -dev, -test, -old)..."
awk -v d="$DOMAIN" '
{
  host=$0
  if (host ~ ("\\." d"$")) {
    base = host
    sub("\\." d"$", "", base)
    if (base != "" && base != d) {
      print host
      print "www-" base "." d
      print base "-dev." d
      print base "-test." d
      print base "-old." d
    } else {
      print host
    }
  } else {
    print host
  }
}' "$ALL_OUT" | sort -u > "${ALL_OUT}.tmp"
mv "${ALL_OUT}.tmp" "$ALL_OUT"
log "After permutations -> $(wc -l < "$ALL_OUT") entries"

# --------- Resolve candidates (dnsx -> massdns -> dig) ----------
log "Resolving candidates..."
: > "$RES_OUT"
if command -v dnsx >/dev/null 2>&1; then
  # use dnsx with minimal flags, capture output and normalize
  TMPRES="$TMPDIR/dnsx_res.txt"
  set +e
  dnsx -a < "$ALL_OUT" > "$TMPRES" 2>/dev/null
  rc=$?
  set -e
  if [ $rc -ne 0 ] || [ ! -s "$TMPRES" ]; then
    # try alternate dnsx invocation
    dnsx < "$ALL_OUT" > "$TMPRES" 2>/dev/null || true
  fi
  awk '{print $1, $2}' "$TMPRES" 2>/dev/null | sed '/^\s*$/d' | sort -u > "$RES_OUT" || true
elif command -v massdns >/dev/null 2>&1; then
  RESOLVER_FILE="$TMPDIR/resolvers.txt"
  if [ -f /etc/resolv.conf ]; then
    grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | sed '/^$/d' > "$RESOLVER_FILE" || true
  fi
  [ ! -s "$RESOLVER_FILE" ] && echo "1.1.1.1" > "$RESOLVER_FILE"
  awk '{print $0 " A"}' "$ALL_OUT" > "$TMPDIR/massdns_input.txt"
  massdns -r "$RESOLVER_FILE" -t A -o S -w "$TMPDIR/massdns_out.txt" "$TMPDIR/massdns_input.txt" 2>/dev/null || true
  awk '/ A / {print $1 " " $3}' "$TMPDIR/massdns_out.txt" | sed 's/\.$//' | sort -u > "$RES_OUT" || true
else
  # fallback: dig sequential or parallel
  if command -v xargs >/dev/null 2>&1; then
    cat "$ALL_OUT" | xargs -n1 -P "$PARALLEL" -I{} bash -c 'ips="$(dig +short "{}" A | tr "\n" " ")"; if [ -n "$ips" ]; then printf "%s %s\n" "{}" "$ips"; fi' 2>/dev/null >> "$RES_OUT" || true
  else
    while read -r h; do ips="$(dig +short "$h" A | tr "\n" " ")"; [ -n "$ips" ] && printf "%s %s\n" "$h" "$ips" >> "$RES_OUT"; done < "$ALL_OUT"
  fi
fi

log "Resolved -> $( [ -f "$RES_OUT" ] && wc -l < "$RES_OUT" || echo 0 ) entries"

# --------- HTTP Probe (httpx or curl fallback) ----------
if $PROBE_HTTP; then
  log "Probing HTTP/HTTPS (httpx if available, else curl)..."
  # make sure HTTP_OUT path exists or create empty file so wc -l won't fail later
  : > "$HTTP_OUT"

  if command -v httpx >/dev/null 2>&1; then
    TMPHTTP="$TMPDIR/httpx_out.txt"
    # try robust invocation: avoid failing if version lacks -silent
    set +e
    httpx -status-code -mc 200,301,302,401,403 -l <(cut -d' ' -f1 "$RES_OUT" | sort -u) -o "$TMPHTTP" 2>/dev/null
    rc=$?
    set -e
    if [ $rc -ne 0 ] || [ ! -s "$TMPHTTP" ]; then
      # fallback to simpler invocation (some httpx versions accept -l file)
      httpx -l <(cut -d' ' -f1 "$RES_OUT" | sort -u) -status-code -o "$TMPHTTP" 2>/dev/null || true
    fi
    # httpx outputs: "http://host:port [status]" or csv depending on version; keep lines that look like host
    if [ -f "$TMPHTTP" ]; then
      # normalize to "host status"
      awk '{ for(i=1;i<=NF;i++){ if ($i ~ /^http/) { host=$i; } if ($i ~ /^[0-9]{3}$/) { status=$i } } if (host!="") { gsub(/https?:\/\//,"",host); split(host,a,"/"); print a[1] " " (status?status:""); } }' "$TMPHTTP" | sed '/^\s*$/d' | sort -u > "$HTTP_OUT" || true
    fi
  else
    # curl fallback: check simple status codes for each host (sequential)
    while read -r host ip; do
      # try https then http, timeout 6s
      for proto in "https" "http"; do
        set +e
        status=$(curl -k -I -s -o /dev/null -w "%{http_code}" --max-time 6 "${proto}://${host}" 2>/dev/null)
        set -e
        if [ -n "$status" ] && [ "$status" != "000" ]; then
          echo "${host} ${status}" >> "$HTTP_OUT"
          break
        fi
      done
    done < "$RES_OUT"
    sort -u "$HTTP_OUT" -o "$HTTP_OUT" || true
  fi

  log "Live -> $( [ -f "$HTTP_OUT" ] && wc -l < "$HTTP_OUT" || echo 0 ) entries"
else
  log "HTTP probe disabled."
fi

# --------- Final Summary ----------
echo -e "\n${CLR_BOLD}Summary:${CLR_RESET}"
echo -e "${CLR_GREEN}Passive (crt.sh):${CLR_RESET} $( [ -f "$CRT_OUT" ] && wc -l < "$CRT_OUT" || echo 0 )"
echo -e "${CLR_GREEN}Brute found:         ${CLR_RESET} $( [ -f "$BRUTE_OUT" ] && wc -l < "$BRUTE_OUT" || echo 0 )"
echo -e "${CLR_GREEN}Combined total:      ${CLR_RESET} $( [ -f "$ALL_OUT" ] && wc -l < "$ALL_OUT" || echo 0 )"
echo -e "${CLR_GREEN}Resolved (host IP):  ${CLR_RESET} $( [ -f "$RES_OUT" ] && wc -l < "$RES_OUT" || echo 0 )"
echo -e "${CLR_GREEN}Live web hosts:      ${CLR_RESET} $( [ -f "$HTTP_OUT" ] && wc -l < "$HTTP_OUT" || echo 0 )"

echo -e "\nResults saved in: ${CLR_BOLD}$OUTDIR${CLR_RESET}"
echo -e " - Passive certs: ${CRT_OUT}"
echo -e " - Brute results: ${BRUTE_OUT}"
echo -e " - Combined list : ${ALL_OUT}"
echo -e " - Resolved list : ${RES_OUT}"
echo -e " - Live web list : ${HTTP_OUT}"

exit 0
