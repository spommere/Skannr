#!/usr/bin/env bash
# Refresh the seven bundled IEEE and Bluetooth SIG registry files.

set -euo pipefail
umask 022

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
data_dir="$repo_dir/src/skannr/data/collectors"

die() {
    echo "update_collector_data.sh: $*" >&2
    exit 1
}

command -v curl >/dev/null 2>&1 || die "curl is required"
[ -d "$data_dir" ] || die "collector data directory not found: $data_dir"

# Stage all downloads beside their destinations. Nothing is replaced until all
# seven downloads pass basic format checks.
tmp_dir=$(mktemp -d "$data_dir/.collector-refresh.XXXXXX")
install_started=0
cleanup() {
    local status=$?
    trap - EXIT
    if [ "$status" -ne 0 ] && [ "$install_started" -eq 1 ]; then
        for data_file in \
            oui.txt mam.txt oui36.txt iab.txt \
            company_identifiers.yaml member_uuids.yaml service_class.yaml \
            company_identifiers.txt member_uuids.txt service_class.txt; do
            if [ -f "$tmp_dir/backup/$data_file" ]; then
                cp -p -- "$tmp_dir/backup/$data_file" "$data_dir/$data_file" || true
            else
                rm -f -- "$data_dir/$data_file" || true
            fi
        done
    fi
    rm -rf -- "$tmp_dir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

download() {
    local url=$1
    local name=$2
    curl --fail --location --silent --show-error \
        --retry 3 --connect-timeout 20 --max-time 300 \
        --output "$tmp_dir/$name" "$url"
    [ -s "$tmp_dir/$name" ] || die "empty download: $url"
    if grep -Eqi '<!doctype html|<html([[:space:]>]|$)' "$tmp_dir/$name"; then
        die "received HTML instead of a data file from: $url"
    fi
}

validate_ieee() {
    local name=$1
    grep -Eqi '\(hex\)|\(base 16\)' "$tmp_dir/$name" ||
        die "unexpected IEEE registry format: $name"
}

download 'https://standards-oui.ieee.org/oui/oui.txt' oui.txt
download 'https://standards-oui.ieee.org/oui28/mam.txt' mam.txt
download 'https://standards-oui.ieee.org/oui36/oui36.txt' oui36.txt
download 'https://standards-oui.ieee.org/iab/iab.txt' iab.txt

for ieee_file in oui.txt mam.txt oui36.txt iab.txt; do
    validate_ieee "$ieee_file"
done

download \
    'https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml' \
    company_identifiers.yaml
grep -q '^company_identifiers:[[:space:]]*$' "$tmp_dir/company_identifiers.yaml" ||
    die "unexpected Bluetooth company identifier YAML format"
grep -qE '^[[:space:]]+- value:' "$tmp_dir/company_identifiers.yaml" ||
    die "company identifier YAML has no entries"

download \
    'https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/uuids/member_uuids.yaml' \
    member_uuids.yaml
download \
    'https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/uuids/service_class.yaml' \
    service_class.yaml
for uuid_file in member_uuids.yaml service_class.yaml; do
    grep -q '^uuids:[[:space:]]*$' "$tmp_dir/$uuid_file" ||
        die "unexpected Bluetooth UUID YAML format: $uuid_file"
    grep -qE '^[[:space:]]+- uuid:' "$tmp_dir/$uuid_file" ||
        die "Bluetooth UUID YAML has no entries: $uuid_file"
done

# All downloads are valid. Install the upstream files verbatim, retaining YAML
# sources as YAML and IEEE registries as text. Drop the former converted names.
mkdir "$tmp_dir/backup"
for data_file in \
    oui.txt mam.txt oui36.txt iab.txt \
    company_identifiers.yaml member_uuids.yaml service_class.yaml \
    company_identifiers.txt member_uuids.txt service_class.txt; do
    if [ -f "$data_dir/$data_file" ]; then
        cp -p -- "$data_dir/$data_file" "$tmp_dir/backup/$data_file"
    fi
done

install_started=1
for data_file in \
    oui.txt mam.txt oui36.txt iab.txt \
    company_identifiers.yaml member_uuids.yaml service_class.yaml; do
    mv -f -- "$tmp_dir/$data_file" "$data_dir/$data_file"
    chmod 0644 "$data_dir/$data_file"
done
rm -f -- \
    "$data_dir/company_identifiers.txt" \
    "$data_dir/member_uuids.txt" \
    "$data_dir/service_class.txt"

echo "Updated seven registry files in $data_dir"
