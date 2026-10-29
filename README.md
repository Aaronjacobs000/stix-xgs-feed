# stix-xgs-feed

Turns STIX threat intel into the three plain-text files that Sophos Firewall (SFOS v21 and later) polls as **third-party threat feeds**:

| File | Firewall indicator type | Content |
|---|---|---|
| `ips.txt` | IPv4 address | one IPv4 address per line |
| `domains.txt` | Domain | one domain per line |
| `urls.txt` | URL | one `http(s)://` URL per line |

Unofficial proof of concept. Not a Sophos product, not supported by Sophos, and not part of Sophos Fusion.

## What the firewall accepts

From the [Sophos Firewall help](https://docs.sophos.com/nsg/sophos-firewall/23.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/ActiveThreatResponse/ConfigureFeeds/ThirdPartyThreatFeeds/ConfigureThirdPartyThreatFeeds/index.html) (same text in 22.0 and 23.0):

- Plain text, one indicator per line. One feed entry per indicator type, so a source with all three types needs three entries.
- Not supported: IP ranges, IPv6, network addresses (CIDR), wildcard domains, regular expressions.
- Auth: none, API key (header or query parameter, value up to 64 characters) or basic auth (password up to 64 characters). Optional server certificate validation; a private CA must be uploaded to the firewall.
- Polling: 5 min, 15 min, 30 min, 1 h, 6 h, 24 h, 7 days, 30 days ([XML API reference](https://docs.sophos.com/nsg/sophos-firewall/21.0/api/protect/active%20threat%20response/thirdpartyfeeds/operations/AddThird-partythreatfeed&EditThird-partythreatfeed.html)). XGS 87, 88 and 107 only offer 24 h, 7 days and 30 days.
- An HTTP 302 is reported as a connection error ([Manage feeds](https://docs.sophos.com/nsg/sophos-firewall/23.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/ActiveThreatResponse/ConfigureFeeds/ThirdPartyThreatFeeds/ManageThirdPartyThreatFeeds/index.html)), so serve the files directly with no redirect.
- No per-feed indicator limit, but a per-model storage quota shared by all third-party feeds on the box ([KBA-000010056](https://support.sophos.com/support/s/article/KBA-000010056?language=en_US)). XGS 107 tops out around 180k IPv4 or 98k domains or 18k URLs in total.
- Needs the Xstream Protection bundle ([licences](https://docs.sophos.com/nsg/sophos-firewall/23.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/ActiveThreatResponse/Requirements/Licenses/index.html)). URL matching on HTTPS needs decryption ([requirements](https://docs.sophos.com/nsg/sophos-firewall/23.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/ActiveThreatResponse/Requirements/OtherConfigurations/index.html)).

## What it does

- **Inputs, mixed freely in one run:** STIX 2.0/2.1 bundles (file or URL), TAXII 2.1 collections (paginated, basic auth or API-key header, `added_after`), STIX 1.x XML packages (file or URL).
- **Extracts** IPv4, IPv6, domains and URLs from STIX patterns (`=`, `IN`, `ISSUBSET`, `OR`, `AND`, `FOLLOWEDBY`, `network-traffic:dst_ref.value`, `START/STOP`) and from bare observables (SCOs, STIX 2.0 `observed-data`, STIX 1.x CybOX Address, DomainName, Hostname and URI objects, `##comma##` lists).
- **Drops** revoked and expired indicators, superseded versions, values under negation (`!=`, `NOT`), `LIKE`/`MATCHES`, non-STIX patterns (Snort, YARA, Sigma), CIDRs, wildcards, internal addresses (RFC 1918, CGNAT, loopback, link-local, multicast, `.corp`, `.local` and similar), non-HTTP URLs, and anything on your allowlist. Every drop is counted by reason.
- **Normalises:** refangs (`hxxp`, `[.]`, `(.)`, `[:]`), lower-cases hosts, converts IDNs to punycode, removes default ports and fragments, percent-encodes paths, dedupes, sorts.
- **Respects limits:** `--model` checks the estimated share of the box's feed storage and trims to the highest-confidence, newest entries if over `--quota-share`.
- **Fails closed:** if any source fails to load, nothing is written and the firewall keeps polling the last good files. Files are replaced atomically, so a poll never sees half a file.

Standard library only, Python 3.9 or later. No install step.

## Run it

```sh
# TAXII 2.1 collection plus a local STIX 1.x export
export TAXII_PASSWORD='...'
python3 stix_xgs_feed.py \
  --taxii https://taxii.example.org/api1/collections/<collection-id>/ --taxii-user feeduser \
  --added-after 2026-08-01T00:00:00Z \
  --input isac-export.xml \
  --allowlist allowlist.txt --min-confidence 50 --max-age-days 90 \
  --model "XGS 2100" --quota-share 0.5 \
  --out /var/www/feeds/acme --report /var/log/stix-xgs-feed/acme.json
```

API-key sources: `--header 'X-Api-Key: env:FEED_KEY'` reads the value from the environment. Credentials go to `--taxii` sources only; `--input` URLs are fetched without them, and a redirect to another host drops them. `python3 stix_xgs_feed.py --help` lists every option.

Defaults worth knowing:

| Option | Default | Why |
|---|---|---|
| `--observables` | `linked` | Bare SCOs only count when a relationship ties them to a valid indicator, malware, infrastructure, threat actor, intrusion set, campaign or tool. Feeds often carry victim or benign observables. `all` takes every SCO, `none` takes only patterns. |
| `--broaden` | off | `[network-traffic:dst_ref.value = 'x' AND network-traffic:dst_port = 4444]` means "x on port 4444". Publishing x alone blocks every port, so compound patterns are dropped unless you opt in. |
| `--max-tlp` | `amber` | RED and AMBER+STRICT are not published. Use `amber+strict` only when the files stay inside one organisation. Objects with no TLP marking pass. |
| `--min-confidence` | 0 | Objects without a confidence value always pass. |
| `--expand-cidr` | off | `--expand-cidr 28` turns a /28 or smaller into single addresses. Larger ranges are always dropped. |

## Schedule it

Each run rebuilds the full set, so a schedule a little faster than the firewall's polling interval is enough.

```cron
*/30 * * * * cd /opt/stix-xgs-feed && . ./feed.env && python3 stix_xgs_feed.py ... >> /var/log/stix-xgs-feed/run.log 2>&1
```

On macOS use a launchd agent; on Windows a Task Scheduler job. The exit code is non-zero on any source failure, so alert on it.

## Serve it over HTTPS

Any HTTPS server or object store that serves the files directly works. Serve only the `.txt` files, keep the JSON report elsewhere, and give each customer its own path and credentials. Example with Caddy (automatic public certificate):

```caddy
feeds.example.com {
	root * /var/www/feeds
	basic_auth {
		xgs-acme <hash from: caddy hash-password>
	}
	@notfeed not path *.txt
	respond @notfeed 404
	file_server
}
```

Then on the firewall, **Active threat response > Third-party threat feeds > Add**, three times:

| Name | Indicator type | URL |
|---|---|---|
| `stix_ips` | IPv4 address | `https://feeds.example.com/acme/ips.txt` |
| `stix_domains` | Domain | `https://feeds.example.com/acme/domains.txt` |
| `stix_urls` | URL | `https://feeds.example.com/acme/urls.txt` |

Start with action **Monitor**, check the Active threat response logs for hits on business traffic for a week or two, then switch to **Block**.

## The allowlist

`allowlist.example.txt` is a starting point. IPs and CIDRs apply to `ips.txt`; a domain removes itself and every subdomain from `domains.txt`; a URL prefix applies to `urls.txt`. A domain entry deliberately does not exempt URLs on that host: an exact malicious URL on `raw.githubusercontent.com` is worth blocking, the whole domain is not. Real public STIX data names `raw.githubusercontent.com`, `codeload.github.com` and `cdn.discordapp.com` as malicious domains, which is why the allowlist matters.

## What it does not do

- TAXII 1.1 polling. STIX 1.x is read from files or plain URLs only.
- IPv6, CIDR ranges, wildcards, regex or file hashes on the firewall, because SFOS does not accept them. `--ipv6-file` writes IPv6 to a separate file for other uses.
- Configure firewalls. The three feed entries are set up once per firewall (UI or XML API).
- Keep state between runs, verify signed content, or apply STIX granular markings.
- Anything in Sophos Fusion.

Not verified on a firewall yet: how SFOS treats an empty file, comment lines, and whether a domain entry also matches its subdomains. The tool writes no comments and warns when a file is empty.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

`tests/data/mixed-bundle.json` is a hand-made STIX 2.1 bundle with one case per rule: compound patterns, negation, `LIKE`/`MATCHES`, CIDRs, expired, not yet valid, revoked and superseded versions, defanged values, TLP RED and AMBER+STRICT, low confidence, Snort and hash indicators, IDN, URL variants, internal addresses, allowlist hits, linked and unlinked observables, and one deliberately malformed pattern. Apart from that malformed pattern, it validates clean with the OASIS `stix2` and `stix2-patterns` libraries.
