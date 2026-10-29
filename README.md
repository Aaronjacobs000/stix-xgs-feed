# stix-xgs-feed

Turns STIX threat intel into the three plain-text files that Sophos Firewall (SFOS v21 and later) polls as **third-party threat feeds**, and can serve them to the firewall over HTTPS.

| File | Firewall indicator type | Content |
|---|---|---|
| `ips.txt` | IPv4 address | one IPv4 address per line |
| `domains.txt` | Domain | one domain per line |
| `urls.txt` | URL | one `http(s)://` URL per line |

**Unofficial tool.** Not a Sophos product, not supported by Sophos, and not part of Sophos Fusion. Test it on a lab firewall before you rely on it.

## Contents

- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [Config file](#config-file)
- [Source authentication](#source-authentication)
- [Serve mode](#serve-mode)
- [Security guidance](#security-guidance)
- [Private CA for the firewall](#private-ca-for-the-firewall)
- [Firewall setup](#firewall-setup)
- [Docker](#docker)
- [Without serve mode](#without-serve-mode)
- [Filtering and the allowlist](#filtering-and-the-allowlist)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Tests](#tests)

## What it does

- **Reads**, mixed freely in one run: STIX 2.0/2.1 bundles (file or URL), TAXII 2.1 collections (paginated, `added_after`), and STIX 1.x XML packages (file or URL).
- **Authenticates** to private sources: basic auth, API key (header or query parameter), bearer token, and client certificates (mTLS), set per source. Secrets come from environment variables or files, never the command line or the config file. Credentials only go to the source's own host and are dropped on any redirect.
- **Extracts** IPv4, IPv6, domains and URLs from STIX patterns (`=`, `IN`, `ISSUBSET`, `OR`, `AND`, `FOLLOWEDBY`, `network-traffic:dst_ref.value`, `START/STOP`) and from bare observables (SCOs, STIX 2.0 `observed-data`, STIX 1.x CybOX Address, DomainName, Hostname and URI objects, `##comma##` lists).
- **Drops** revoked and expired indicators, superseded versions, values under negation (`!=`, `NOT`), `LIKE`/`MATCHES`, non-STIX patterns (Snort, YARA, Sigma), CIDRs, wildcards, internal addresses (RFC 1918, CGNAT, loopback, link-local, multicast, `.corp`, `.local` and similar), non-HTTP URLs, TLP:RED and AMBER+STRICT, and anything on your allowlist. Every drop is counted by reason.
- **Normalizes**: refangs (`hxxp`, `[.]`, `(.)`, `[:]`), lowercases hosts, converts IDNs to punycode, removes default ports and fragments, percent-encodes paths, dedupes and sorts.
- **Respects limits**: `model` checks the estimated share of the firewall's feed storage and trims to the highest-confidence, newest entries when over `quota_share`.
- **Fails closed**: if any source fails, nothing is written and the firewall keeps polling the last good files. Each file is replaced atomically, so a poll never sees half a file.
- **Serves** (optional, off by default): `stix-xgs-feed serve` serves the three files over TLS with basic or API-key auth, never redirects, and rebuilds them on a schedule.

Standard library only, no third-party packages. Python 3.9 or later; TOML config files need Python 3.11 or later (3.9 and 3.10 can use the same settings as a `.json` file). The Docker image uses Python 3.13.

## Quick start

From a checkout, run it as `python3 -m stix_xgs_feed`. Or `pip install .` once and use the `stix-xgs-feed` command. The examples use the command.

**One-off run from flags:**

```sh
stix-xgs-feed -i https://intel.example.com/stix/bundle.json -i isac-export.xml \
  --allowlist allowlist.example.txt --min-confidence 50 -o feeds
```

**One run from a config file** (sources with their own credentials, filters, limits, output):

```sh
cp config.example.toml config.toml        # then edit it
export ISAC_PASSWORD='...'                # whatever env: references the config uses
stix-xgs-feed --config config.toml
```

**Serve the files to the firewall** (needs the `[serve]` section; see [Serve mode](#serve-mode)). For the firewall to reach it, set `listen` to the address it polls and `allowed_clients` to the firewall's address:

```sh
scripts/make-private-ca.sh pki feeds.example.lan 192.0.2.10
mkdir -p tls && cp pki/server.pem pki/server.key tls/
export FEED_PASSWORD=$(openssl rand -hex 24)   # 48 characters; the firewall allows 64
stix-xgs-feed serve --config config.toml --check
stix-xgs-feed serve --config config.toml
```

**Docker**: see [Docker](#docker).

`stix-xgs-feed --help`, `stix-xgs-feed serve --help` and `stix-xgs-feed healthcheck --help` list every option.

## Config file

TOML (`.toml`) or JSON (`.json`) with the same structure. [`config.example.toml`](config.example.toml) shows every setting. Relative paths resolve against the config file's folder. Unknown keys are errors, so a typo fails loudly instead of being ignored.

`--config` cannot be mixed with the source, filter or output flags (only with `--now`). Use flags for quick one-off runs and a config file for anything with credentials or a schedule.

### `[[sources]]` (one table per source, at least one)

| Key | Applies to | Default | Meaning |
|---|---|---|---|
| `type` | all | required | `taxii`, `url` (STIX 2.x JSON or STIX 1.x XML over HTTP(S)) or `file` |
| `name` | all | `sourceN` | Used in logs and errors. Must be unique. |
| `url` | `taxii`, `url` | required | For TAXII, the collection URL (`.../collections/<id>/`). No `user:pass@` in the URL. |
| `path` | `file` | required | Local STIX file. |
| `ca_file` | `taxii`, `url` | system store | PEM CA bundle for a server with a private certificate. Only that CA is trusted. |
| `timeout` | `taxii`, `url` | 120 | Seconds per request. |
| `added_after` | `taxii` | none | TAXII `added_after` filter, e.g. `2026-08-01T00:00:00Z`. |
| `page_size` | `taxii` | server default | TAXII `limit` parameter. |
| `max_pages` | `taxii` | 10000 | Stop after this many pages. |

### `[sources.auth]` (optional, `taxii` and `url` sources)

| Key | Used with | Meaning |
|---|---|---|
| `type` | | `none` (default), `basic`, `api_key` or `bearer` |
| `username` | `basic` | Plain value. |
| `password` | `basic` | Secret reference. |
| `key_name` | `api_key` | Header or query parameter name, e.g. `X-Api-Key`. |
| `key_value` | `api_key` | Secret reference. |
| `add_to` | `api_key` | `header` (default) or `query`. |
| `token` | `bearer` | Secret reference. Sent as `Authorization: Bearer <token>`. |
| `client_cert`, `client_key` | any type | PEM client certificate and key for mTLS. HTTPS only. |
| `client_key_password` | with `client_key` | Secret reference, for an encrypted key. |
| `[sources.auth.headers]` | any type | Extra headers. A value is either plain text or a secret reference. |

### `[output]` (required)

| Key | Default | Meaning |
|---|---|---|
| `dir` | required | Folder for `ips.txt`, `domains.txt` and `urls.txt`. |
| `report` | none | JSON run report: counts, drop reasons, parse errors. Keep it outside `dir`. |
| `ipv6_file` | `false` | Also write `ipv6.txt`. Sophos Firewall feeds do not accept IPv6, and serve mode never serves it. |

### `[filter]` and `[limits]` (optional)

The same settings as the command-line flags of the same name; see [Filtering and the allowlist](#filtering-and-the-allowlist). `[filter]`: `observables`, `broaden`, `min_confidence`, `max_tlp`, `max_age_days`, `allowlist`, `keep_internal`, `expand_cidr`. `[limits]`: `model`, `quota_share`, `max_ips`, `max_domains`, `max_urls`.

### `[serve]` and `[serve.auth]` (optional, used by `serve` only)

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1` | IP address to bind, or `localhost`. Anything beyond loopback needs TLS and auth. |
| `port` | 8443 | |
| `path_prefix` | none | Serve under a prefix, e.g. `/acme` gives `/acme/ips.txt`. |
| `tls_cert`, `tls_key` | none | PEM server certificate (with any intermediates) and unencrypted key. |
| `refresh_minutes` | 60 | Rebuild the files this often, measured from the start of each run. 1 to 43200. |
| `retry_minutes` | 5 | After a failed rebuild, try again this soon (never longer than `refresh_minutes`). |
| `allowed_clients` | any | List of IP addresses or networks allowed to fetch the feeds, e.g. `["192.0.2.1"]`. |
| `max_connections` | 32 | Concurrent connections; extra ones are dropped. |
| `auth.type` | `none` | `none`, `basic` or `api_key`. |
| `auth.username`, `auth.password` | | For `basic`. Password is a secret reference. |
| `auth.key_name`, `auth.key_value`, `auth.add_to` | | For `api_key`. `add_to` is `header` (default) or `query`. Value is a secret reference. |

### Secret references

Every secret field takes one of:

- `env:NAME` reads environment variable `NAME`.
- `file:/path` reads the whole file, trimming surrounding whitespace. A relative path resolves against the config file's folder. Works with Docker and Kubernetes secrets.

A plain value in a secret field is refused. Source secrets are read at every refresh, so a rotated secret file is picked up without a restart. Serve secrets are read at start.

## Source authentication

| Source needs | Config |
|---|---|
| Username and password | `type = "basic"`, `username`, `password = "env:..."` |
| API key in a header | `type = "api_key"`, `key_name = "X-Api-Key"`, `key_value = "env:..."` |
| API key in the URL | the same with `add_to = "query"` |
| Bearer or OAuth access token | `type = "bearer"`, `token = "file:..."` |
| Client certificate | `client_cert` and `client_key`, alone or with any type above |
| Private server certificate | `ca_file` on the source |

How credentials are protected:

- **Pinned to the source's origin.** Auth headers, the API key parameter and the client certificate are only sent to the scheme, host and port of the configured URL.
- **Dropped on any redirect.** A redirected request goes out with no credentials, no API key parameter (even if the server copied it into the `Location`) and no client certificate. If a source redirects and then answers 401, point the config at the final URL.
- **HTTPS only.** Credentials are refused over plain HTTP, except to a loopback address for local testing. A redirect from HTTPS to plain HTTP is refused. At most 5 redirects.
- **Never logged.** Errors and logs show the scheme, host and path of a URL, never the query string, headers or secret values.

On the command line, the credential flags (`--taxii-user` with `--taxii-password-env`, `--bearer`, `--header`, `--client-cert`, `--client-key`, `--client-key-password`) apply to `--taxii` sources only, and secret values must be `env:` or `file:` references. `--input` URLs are always fetched without credentials. For an authenticated plain STIX URL, or different credentials per source, use a config file.

## Serve mode

`stix-xgs-feed serve --config config.toml` runs a small HTTPS server and a scheduler in one process:

- **Serves three files and nothing else**: `ips.txt`, `domains.txt` and `urls.txt` under `path_prefix`, with `GET` and `HEAD`. Every other path is a 404, other methods a 405. No directory listing, no `ipv6.txt`, no report.
- **Never redirects.** Sophos Firewall reports a 302 as a connection error, so there is no 3xx response at all, not even for a trailing slash.
- **Authenticates** with what the firewall supports: none, basic auth, or an API key in a header or query parameter. Credentials are compared in constant time. An unauthenticated `GET` gets a 401 for every path except `/healthz`, so it learns nothing about which paths exist. The firewall caps the key name, key value, username and password at 64 characters; serve mode enforces that, and requires passwords and keys of 16 to 64 printable ASCII characters without spaces.
- **TLS** 1.2 or later from your certificate and key.
- **Refreshes** at start and then every `refresh_minutes`, retrying after `retry_minutes` when a run fails. A failed run changes nothing, so the firewall keeps getting the last good files. Each file is written to a temporary file and renamed into place, so a request gets the old file or the new one, never part of either. Files live in `output.dir`, so after a restart the last good set is served at once.
- **Health**: `GET /healthz` needs no credentials and returns `200 ok` once all three files exist, else `503 unavailable`. Nothing else: no counts, times, versions or source names.
- **Logs** to stderr: one line per request (client address, method, path without query string, status, bytes), authentication failures as warnings, and each refresh result. Never credentials or query strings.
- **Limits**: `allowed_clients` drops connections from other addresses before the TLS handshake (loopback may still call `/healthz`). `max_connections` caps concurrent connections.

It refuses to start when:

- `listen` is beyond loopback and TLS or authentication is missing.
- A password or API key is over 64 characters, under 16, or has spaces or non-ASCII characters.
- A secret reference cannot be read, or the certificate and key do not load.
- Any source secret or client certificate cannot be loaded (checked at start, not at the first refresh).

`serve --check` runs all of those checks and exits without serving. `stix-xgs-feed healthcheck --config config.toml` exits 0 when the local instance answers `/healthz` with 200 (used by the Docker health check; it skips certificate validation because it only talks to its own loopback listener).

Stop it with Ctrl+C or SIGTERM.

## Security guidance

**Recommended: on the LAN or in a DMZ, reachable only by the firewall.**

- Bind to the LAN or DMZ address (or `0.0.0.0` in a container) and set `allowed_clients` to the firewall's address. Add a host firewall or ACL rule that does the same.
- Use TLS with a private CA the firewall trusts ([below](#private-ca-for-the-firewall)) and tick **Validate server certificate** on each feed. Without validation, anyone who can intercept the connection can feed the firewall a block list.
- Use basic auth or an API key in a header with a random value: `openssl rand -hex 24` gives 48 characters. Avoid `add_to = "query"` where you can, because query strings end up in proxy and web logs.
- One instance, or one `path_prefix` and credential, per customer.

**Internet-facing: do not expose `serve` directly.** It has no rate limiting, lockout or public certificate automation. Put a reverse proxy in front that does, and keep `serve` on loopback. Example with Caddy (automatic public certificate):

```caddy
feeds.example.com {
	@feeds path /acme/ips.txt /acme/domains.txt /acme/urls.txt
	handle @feeds {
		basic_auth {
			xgs-acme <hash from: caddy hash-password>
		}
		reverse_proxy 127.0.0.1:8443
	}
	respond 404
}
```

With `listen = "127.0.0.1"`, no `tls_cert`, `path_prefix = "/acme"` and `serve.auth` set to `none` (Caddy does the auth; serve mode logs a warning about it). In Docker, run Caddy with `network_mode: "service:stix-xgs-feed"` so loopback is shared.

Not handled by serve mode, so plan for them: rate limiting and lockout after failed logins, certificate reload (restart after renewing), and alerting when refreshes keep failing (watch the logs for `refresh failed`).

## Private CA for the firewall

The firewall can validate the feed server's certificate against a CA you upload. `scripts/make-private-ca.sh` makes one with OpenSSL (or LibreSSL):

```sh
scripts/make-private-ca.sh pki feeds.example.lan 192.0.2.10
```

List every DNS name or IP address the firewall will use in the feed URL; the first becomes the common name. It writes:

| File | Use |
|---|---|
| `pki/ca.pem` | Upload to the firewall. Valid 10 years. |
| `pki/ca.key` | Keep offline. Only needed to issue the next server certificate. |
| `pki/server.pem` | `serve.tls_cert`. Valid 397 days. |
| `pki/server.key` | `serve.tls_key`. Readable by the service user only. |

Then on the firewall:

1. **Certificates > Certificate authorities > Add**, upload `pki/ca.pem`.
2. On each feed entry, tick **Validate server certificate**.

To renew, run the same command again with the same folder. It reuses `ca.pem` and `ca.key`, so the firewalls need no change. Copy the new `server.pem` and `server.key` into place and restart `serve`.

A certificate from your organization's own CA works the same way: upload that CA instead. A public certificate (for example through the Caddy setup above) needs no upload if its CA is already in the firewall's list.

## Firewall setup

Requirements: SFOS v21 or later, the **Xstream Protection** license ([licenses](https://docs.sophos.com/nsg/sophos-firewall/23.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/ActiveThreatResponse/Requirements/Licenses/index.html)), and HTTPS decryption if URL entries must match HTTPS traffic ([requirements](https://docs.sophos.com/nsg/sophos-firewall/23.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/ActiveThreatResponse/Requirements/OtherConfigurations/index.html)).

**Active threat response > Third-party threat feeds > Add**, once per file ([help](https://docs.sophos.com/nsg/sophos-firewall/23.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/ActiveThreatResponse/ConfigureFeeds/ThirdPartyThreatFeeds/ConfigureThirdPartyThreatFeeds/index.html)):

| Field | Value |
|---|---|
| Name | e.g. `stix_ips`, `stix_domains`, `stix_urls` (letters, numbers, `_` and `-`, up to 63 characters) |
| Action | **Monitor** first. Switch to **Block** after a week or two of clean logs. |
| Position | Top or Bottom |
| Indicator type | **IPv4 address**, **Domain** or **URL**, matching the file. The firewall only evaluates the selected type. |
| External URL | `https://feeds.example.lan:8443/acme/ips.txt` and so on (up to 1024 characters) |
| Authorization | **Basic authentication** with `serve.auth.username` and the password, or **API key** with `key_name`, the key, and **Header** or **Query parameters** matching `add_to` |
| Validate server certificate | Ticked, after uploading the CA |
| Polling interval | 5 min, 15 min, 30 min, 1 h, 6 h, 24 h, 7 days or 30 days. XGS 87, 88 and 107 offer only 24 h, 7 days and 30 days. |

Use **Test connection**, save, then check **Sync status**. Set `refresh_minutes` at or below the polling interval.

Configuration is per firewall. There is no Sophos Fusion group policy for third-party feeds, and the firewall cannot import or export them, but the [XML API](https://docs.sophos.com/nsg/sophos-firewall/21.0/api/protect/active%20threat%20response/thirdpartyfeeds/operations/AddThird-partythreatfeed&EditThird-partythreatfeed.html) can script the three entries per box.

### Storage limits

There is no per-feed indicator limit, but each model has a storage quota shared by every third-party feed on the box ([KBA-000010056](https://support.sophos.com/support/s/article/KBA-000010056?language=en_US), checked 2026-10-29). Each figure below is the whole quota for that type alone; domains and URLs assume average lengths of 64 and 512 characters.

| Model | IPv4 | Domains | URLs |
|---|---|---|---|
| XGS 87, 88, 107, 116, virtual, cloud | 180,000 | 98,000 | 18,000 |
| XGS 118, 126 | 270,000 | 140,000 | 28,000 |
| XGS 128, 136, 138, 2100, 2300 | 900,000 | 490,000 | 94,000 |
| XGS 3100, 3300, 4300, 4500 | 2,700,000 | 1,480,000 | 280,000 |
| XGS 5500, 6500 | 4,500,000 | 2,470,000 | 470,000 |
| XGS 7500, 8500 | 8,800,000 | 10,100,000 | 1,900,000 |

Set `model` (e.g. `"XGS 107"`) and `quota_share` (this feed's share when other feeds run on the same box). Over budget, each file is trimmed to its highest-confidence, newest entries and the report records how many were dropped. Desktop models fill fast, URLs especially.

## Docker

The image runs `serve` as a non-root user (uid 10001) on Python 3.13 slim, with a health check. No packages are installed beyond the base image.

```sh
mkdir -p config/tls secrets
cp examples/docker/feed.toml config/feed.toml      # edit sources and allowed_clients
cp allowlist.example.txt config/allowlist.txt      # edit for your estate
scripts/make-private-ca.sh pki feeds.example.lan 192.0.2.10
cp pki/server.pem pki/server.key config/tls/
openssl rand -hex 24 > secrets/feed_password       # the password the firewall sends
# Write each source credential to its own file, e.g. secrets/isac_password,
# with an editor rather than the shell, so it stays out of shell history.
sudo chown 10001:10001 secrets/* config/tls/server.key
sudo chmod 400 secrets/* config/tls/server.key
echo "FEED_BIND_IP=192.0.2.10" > .env              # the host address the firewall polls
docker compose up -d --build
docker compose logs -f
```

- [`compose.yaml`](compose.yaml) mounts `config/` read-only at `/config`, keeps the feed files in the `feed-data` volume at `/data`, passes credentials as compose secrets under `/run/secrets`, and runs with a read-only root filesystem, all capabilities dropped and `no-new-privileges`. Add a compose secret per source credential and reference it as `file:/run/secrets/<name>`.
- The container listens on `0.0.0.0:8443` inside its own network, so TLS and auth are mandatory there. `FEED_BIND_IP` decides which host address publishes it.
- The health check turns healthy after the first successful refresh.
- `docker compose exec stix-xgs-feed python -m stix_xgs_feed serve --config /config/feed.toml --check` validates a changed config before a restart.
- Docker Desktop, and Docker's userland proxy in general, can make every connection look like it comes from the Docker gateway. If the firewall gets 403s or dropped connections, check the client address in the log and adjust `allowed_clients`, or rely on a host firewall rule instead.

Without compose: `docker build -t stix-xgs-feed .`, then `docker run` with the same mounts, secrets and port.

## Without serve mode

The one-off command rebuilds the full set on each run, so a schedule a little faster than the firewall's polling interval is enough. Serve the folder with any web server that serves files directly with no redirect, for example the Caddy `file_server` directive, and expose only the three `.txt` files.

```cron
*/30 * * * * cd /opt/stix-xgs-feed && . ./feed.env && python3 -m stix_xgs_feed --config config.toml >> /var/log/stix-xgs-feed.log 2>&1
```

On macOS use a launchd agent; on Windows a Task Scheduler job. The exit code is 1 when a source fails and 2 for a config error, so alert on non-zero.

## Filtering and the allowlist

Defaults worth knowing (config key, then flag):

| Setting | Default | Why |
|---|---|---|
| `observables` / `--observables` | `linked` | Bare SCOs only count when a relationship ties them to a valid indicator, malware, infrastructure, threat actor, intrusion set, campaign or tool. Feeds often carry victim or benign observables. `all` takes every SCO, `none` only patterns. |
| `broaden` / `--broaden` | off | `[network-traffic:dst_ref.value = 'x' AND network-traffic:dst_port = 4444]` means "x on port 4444". Publishing x alone blocks every port, so compound patterns are dropped unless you opt in. |
| `max_tlp` / `--max-tlp` | `amber` | RED and AMBER+STRICT are not published, because the files sit on a web server. Use `amber+strict` only when the files stay inside one organization. Objects with no TLP marking pass. |
| `min_confidence` / `--min-confidence` | 0 | Objects without a confidence value always pass. |
| `max_age_days` / `--max-age-days` | none | Drops indicators with no `valid_until` whose last change is older than this. |
| `expand_cidr` / `--expand-cidr` | off | `28` turns a /28 or smaller into single addresses (16 to 32). Larger ranges are always dropped. |
| `keep_internal` / `--keep-internal` | off | Keeps private, CGNAT, loopback, link-local, multicast, reserved and internal-suffix values. |

The allowlist is mandatory in practice. [`allowlist.example.txt`](allowlist.example.txt) is a starting point. IPs and CIDRs apply to `ips.txt`; a domain removes itself and every subdomain from `domains.txt`; a URL prefix applies to `urls.txt`. A domain entry deliberately does not exempt URLs on that host: an exact malicious URL on `raw.githubusercontent.com` is worth blocking, the whole domain is not. Real public STIX data names `raw.githubusercontent.com`, `codeload.github.com` and `cdn.discordapp.com` as malicious domains. Give the allowlist an owner.

## Troubleshooting

**Firewall sync status** ([manage feeds](https://docs.sophos.com/nsg/sophos-firewall/23.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/ActiveThreatResponse/ConfigureFeeds/ThirdPartyThreatFeeds/ManageThirdPartyThreatFeeds/index.html)):

| Status | Likely cause here |
|---|---|
| Authentication error | Wrong username, password or key; key sent in the header when `add_to = "query"` (or the other way round); or a TLS handshake failure. The serve log shows `authentication failed from <address>` for credential problems. |
| SSL/TLS error | CA not uploaded, or the External URL's host is not in the certificate's names. Re-run `make-private-ca.sh` with that name or IP. |
| Connection error | Not listening on that address, blocked by `allowed_clients` or a host firewall, a 404 from a wrong path or `path_prefix`, or a 503 because no refresh has succeeded yet. |
| Failed | The file is not what the firewall expects. Fetch the URL with `curl` and check it is one indicator per line. |
| Storage full | Set `model` and `quota_share`, or tighten the filters. |

**Common errors:**

- `refusing to listen on ... without TLS ... and authentication`: set `tls_cert`, `tls_key` and `serve.auth`, or listen on `127.0.0.1` behind a reverse proxy.
- `environment variable X is not set` or `cannot read secret file`: the secret reference points at nothing. In Docker, check the compose secret and its file owner (uid 10001).
- `CERTIFICATE_VERIFY_FAILED` from a source: the server uses a private CA. Set `ca_file` on that source.
- `HTTP 401` from a source that redirects: credentials are not sent on redirects. Use the final URL.
- `credentials are only sent over HTTPS`: the source URL is `http://`. Use `https://`.
- `refresh failed; still serving the previous files`: a source failed. The firewall keeps the last good set; the log line says which source and why.
- A `warning: ... is empty` line: no indicator survived the filters. How the firewall handles an empty feed is not verified yet.

Run with `serve --log-level debug` to see health check requests too. `curl -u xgs:"$FEED_PASSWORD" --cacert pki/ca.pem https://feeds.example.lan:8443/acme/ips.txt` reproduces what the firewall does.

## Limitations

- Not yet verified on a firewall: how SFOS treats an empty file or comment lines (the tool writes none), whether a domain entry also matches its subdomains, and which TLS versions and ciphers the feed client offers (serve mode accepts TLS 1.2 and 1.3 with Python's default ciphers).
- TAXII 1.1 is not supported; STIX 1.x is read from files or plain URLs. TAXII 2.1 discovery is not used; give the collection URL.
- IPv6, CIDR ranges, wildcards, regex and file hashes never reach the firewall, because SFOS does not accept them. `ipv6_file` writes IPv6 to a separate file for other uses.
- No state between runs, no signature checks on STIX content, no STIX granular markings.
- Serve mode has no rate limiting or lockout, does not reload certificates or serve secrets without a restart, and is untested on Windows.
- It does not configure firewalls and has nothing to do with Sophos Fusion.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The tests start local HTTP, HTTPS and TAXII stubs and make throwaway certificates with `openssl` (TLS tests skip without it). They cover every filtering rule (`tests/data/mixed-bundle.json` has one case per rule), each auth type, secret handling, redirect stripping and host pinning, mTLS, the serve refusals, auth and routing, the atomic swap under concurrent load, and the scheduler. Tests that use TOML config files skip on Python older than 3.11. All credentials in the tests are fake.

## License

MIT. See [LICENSE](LICENSE).
