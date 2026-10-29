#!/bin/sh
# Make a private CA and a server certificate for stix-xgs-feed serve.
#
#   scripts/make-private-ca.sh OUT_DIR NAME [NAME ...]
#
# NAME is each DNS name or IP address the firewall will use in the feed URL,
# for example feeds.example.lan 192.0.2.10. The first one becomes the
# certificate's common name.
#
# Writes to OUT_DIR:
#   ca.pem       upload this to the firewall (Certificates > Certificate authorities)
#   ca.key       keep offline; only needed to issue the next server certificate
#   server.pem   serve.tls_cert
#   server.key   serve.tls_key
#
# If OUT_DIR already holds ca.pem and ca.key they are reused, so renewing the
# server certificate does not mean uploading a new CA to every firewall.
set -eu

if [ $# -lt 2 ]; then
  echo "usage: $0 OUT_DIR NAME [NAME ...]" >&2
  exit 2
fi
command -v openssl >/dev/null 2>&1 || { echo "error: openssl not found" >&2; exit 1; }

out=$1
shift
cn=$1
mkdir -p "$out"
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

san=""
for name in "$@"; do
  case $name in
    *:*) entry="IP:$name" ;;                                   # IPv6
    *[!0-9.]*) entry="DNS:$name" ;;                            # anything that is not only digits and dots
    *) entry="IP:$name" ;;                                     # IPv4
  esac
  san="${san:+$san,}$entry"
done

if [ -f "$out/ca.pem" ] && [ -f "$out/ca.key" ]; then
  echo "reusing the CA in $out"
else
  cat > "$work/ca.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = stix-xgs-feed private CA
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
  openssl req -x509 -new -newkey rsa:3072 -nodes -sha256 -days 3650 \
    -keyout "$out/ca.key" -out "$out/ca.pem" -config "$work/ca.cnf" -extensions v3_ca 2>/dev/null
  echo "made a new CA: $out/ca.pem (valid 10 years)"
fi

cat > "$work/server.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = $cn
EOF
cat > "$work/server.ext" <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $san
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
openssl req -new -newkey rsa:3072 -nodes -sha256 \
  -keyout "$out/server.key" -out "$work/server.csr" -config "$work/server.cnf" 2>/dev/null
openssl x509 -req -sha256 -days 397 -in "$work/server.csr" \
  -CA "$out/ca.pem" -CAkey "$out/ca.key" -set_serial "0x$(openssl rand -hex 16)" \
  -extfile "$work/server.ext" -out "$out/server.pem" 2>/dev/null
chmod 644 "$out/ca.pem" "$out/server.pem"
openssl verify -CAfile "$out/ca.pem" "$out/server.pem" >/dev/null
echo "made $out/server.pem for $san (valid 397 days)"
