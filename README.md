# Hacksudo Subdomain Enumerator

**A lightweight, flexible subdomain enumeration script** (Bash) that combines passive certificate scraping (crt.sh) with wordlist-based brute forcing, safe permutations, DNS resolution, and optional HTTP probing. The script intentionally **does not ship any default wordlists** — you supply your own wordlist file.

---

## Features

* Passive discovery via `crt.sh`.
* Wordlist-based brute forcing (user-supplied wordlist only).
* Safe permutations (e.g., `www-<subdomain>`, `<subdomain>-dev`, `<subdomain>-test`, `<subdomain>-old`).
* Resolution using `dnsx` / `massdns` / `dig` fallbacks.
* Optional HTTP(S) probing via `httpx` or `curl` fallback.
* Colorful terminal banner and progress output.
* Produces results in `results/` folder:

  * `<domain>_crt.txt` — passive results
  * `<domain>_bruteforce.txt` — brute-forced subdomains
  * `<domain>_all.txt` — combined unique candidates
  * `<domain>_resolved.txt` — resolved host + IP
  * `<domain>_live.txt` — hosts that responded over HTTP(S)

---

## Requirements

(Install these for best results; script will fallback gracefully when some are missing.)

* `bash` (4+ recommended)
* `curl`
* `dig` (from `dnsutils` / `bind-utils`)
* Optional but strongly recommended:

  * `dnsx` (ProjectDiscovery) — fast DNS resolution
  * `httpx` (ProjectDiscovery) — fast HTTP probing
  * `massdns` — very fast bulk resolution
  * `xargs` — for parallel lookups

---

## How it works

1. Query `crt.sh` for certificates containing the target domain and extract `name_value` entries.
2. Generate candidate hostnames from your provided wordlist: `word + . + domain`.
3. Optionally use `dnsx` (if installed) to filter candidates that resolve.
4. Add non-destructive permutations for common variants.
5. Resolve all candidates with `dnsx` / `massdns` / `dig` fallback.
6. Probe live HTTP(S) endpoints with `httpx` or `curl` fallback.

---

## Usage

1. Make the script executable (once):

```bash
chmod +x hacksudoEnum.sh
```

2. Run the script with your domain and a path to your custom wordlist:

```bash
./hacksudoEnum.sh example.com /path/to/wordlist.txt
```

3. Check outputs in `results/`:

```bash
ls -l results/
cat results/example.com_all.txt
cat results/example.com_resolved.txt
```

---

## Example

```bash
# run with a relative wordlist
./hacksudoEnum.sh hacksudo.com wordlists/large.txt

# view resolved hosts
cat results/hacksudo.com_resolved.txt
# probe live hosts faster with httpx installed
cat results/hacksudo.com_live.txt
```

---

## Tips & Troubleshooting

* If you see many false positives, check for wildcard DNS. Use a random subdomain test to detect wildcards.
* If `dnsx` or `httpx` flags differ between versions, the script has fallbacks; update the tools if you can.
* For very large brute force jobs, consider `massdns` with a good resolver list for speed.
* If `httpx` is missing you'll still get HTTP results via `curl` (slower).

---

## Contributing

Contributions are welcome. If you'd like to add features (AMASS integration, massdns tuning, JSON/CSV output, nmap scanning), please open an issue or submit a pull request.

### Suggested improvements

* Add optional `amass` / `subfinder` passive merge phase.
* Export final results as CSV/JSON.
* Add `--active` amass mode with API key configuration (Shodan, Censys).
* Add optional `nmap` scanning of live hosts.

---

## License

This project is provided under the **MIT License**. See `LICENSE` for details.

---

## Security & Legal

Only run this script against domains and assets you own or have explicit permission to test. Unauthorized scanning or enumeration of third-party domains may be illegal and unethical.

---

## Contact

If you need help or want customizations, open an issue or reach out to the repository owner.
