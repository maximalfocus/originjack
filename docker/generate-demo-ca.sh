#!/usr/bin/env bash
# Generate a throwaway demonstration certificate authority and one server certificate
# per demo origin, at image-build time, inside the container.
#
# Nothing produced here is committed to the repository or trusted anywhere outside the
# demo's own containers, and the CA private key is destroyed in this same layer once the
# server certificates are signed — so the built image cannot issue anything further.
set -euo pipefail

out="${1:?usage: generate-demo-ca.sh OUTPUT_DIR ORIGINS_FILE}"
origins_file="${2:?usage: generate-demo-ca.sh OUTPUT_DIR ORIGINS_FILE}"

ca_dir="$out/ca"
mkdir -p "$ca_dir"

openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
  -keyout "$ca_dir/ca.key" \
  -out "$ca_dir/ca.pem" \
  -subj "/O=originjack demonstration/CN=originjack throwaway demo CA - NOT A REAL CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  2>/dev/null

while IFS= read -r host || [ -n "$host" ]; do
  host="${host%%#*}"
  host="$(printf '%s' "$host" | tr -d '[:space:]')"
  [ -n "$host" ] || continue

  host_dir="$out/$host"
  mkdir -p "$host_dir"

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$host_dir/key.pem" \
    -out "$host_dir/csr.pem" \
    -subj "/O=Meridian Payroll (fictional demonstration)/CN=$host" \
    2>/dev/null

  ext_file="$host_dir/ext.cnf"
  {
    printf 'subjectAltName=DNS:%s\n' "$host"
    printf 'basicConstraints=critical,CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature,keyEncipherment\n'
    printf 'extendedKeyUsage=serverAuth\n'
  } > "$ext_file"

  openssl x509 -req -sha256 -days 825 \
    -in "$host_dir/csr.pem" \
    -CA "$ca_dir/ca.pem" \
    -CAkey "$ca_dir/ca.key" \
    -CAcreateserial \
    -extfile "$ext_file" \
    -out "$host_dir/cert.pem" \
    2>/dev/null

  rm -f "$host_dir/csr.pem" "$ext_file"
  echo "issued demo certificate for $host"
done < "$origins_file"

# The CA private key never survives the build.
rm -f "$ca_dir/ca.key" "$ca_dir"/*.srl
echo "demo CA private key destroyed; only $ca_dir/ca.pem remains"
