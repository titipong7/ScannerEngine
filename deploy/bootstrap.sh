#!/usr/bin/env bash
#
# One-time setup for a fresh Oracle Cloud Ampere A1 instance (Ubuntu 22.04/24.04).
#
#   curl -fsSL https://raw.githubusercontent.com/titipong7/ScannerEngine/main/deploy/bootstrap.sh | bash
#   # or, after cloning:  bash deploy/bootstrap.sh
#
# Installs Docker, opens the ports Oracle's local firewall blocks by default,
# and verifies the one thing that silently breaks every scan: outbound DNS.

set -euo pipefail

log()  { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
warn() { printf '\033[33mwarning: %s\033[0m\n' "$1"; }
die()  { printf '\033[31merror: %s\033[0m\n' "$1" >&2; exit 1; }

[[ $EUID -eq 0 ]] && die "run this as your normal user (it calls sudo itself), not as root"

log "Checking the machine"
ARCH="$(uname -m)"
echo "architecture: $ARCH"
if [[ "$ARCH" != "aarch64" ]]; then
	warn "this is not an ARM64 machine; the image still builds, but the Ampere A1 shape is the free one"
fi

log "Installing Docker and the Compose plugin"
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
	docker.io docker-compose-plugin ca-certificates curl git dnsutils iptables-persistent

sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"

log "Opening ports 80 and 443 in the instance firewall"
# Oracle's Ubuntu images ship an iptables INPUT chain that REJECTs everything
# past a few ports. Adding a VCN security-list rule is NOT enough on its own —
# this is the step people miss when "the port is open but nothing connects".
for port in 80 443; do
	if sudo iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
		echo "port $port: already allowed"
	else
		sudo iptables -I INPUT 1 -p tcp --dport "$port" -j ACCEPT
		echo "port $port: allowed"
	fi
done
sudo netfilter-persistent save >/dev/null
echo "rules saved (they survive a reboot)"

log "Checking outbound DNS — every scan depends on it"
dns_ok=true
for server in 1.1.1.1 8.8.8.8; do
	if dig +short +time=3 +tries=1 @"$server" A example.com >/dev/null 2>&1; then
		echo "UDP 53 to $server: ok"
	else
		warn "cannot reach $server over UDP 53"
		dns_ok=false
	fi
done
if dig +short +tcp +time=3 +tries=1 @1.1.1.1 TXT github.com >/dev/null 2>&1; then
	echo "TCP 53 (large answers): ok"
else
	warn "TCP 53 is blocked — SPF/DKIM lookups with large answers will time out"
	dns_ok=false
fi
$dns_ok || warn "fix egress before deploying, or every scan will come back as 'error'"

cat <<'NEXT'

==> Done. Two things left:

  1. Log out and back in (or run: newgrp docker) so your user can run docker
     without sudo.

  2. In the Oracle console, add ingress rules to this subnet's security list:
       TCP 80  from 0.0.0.0/0
       TCP 443 from 0.0.0.0/0
     The firewall rules above only cover the instance; the VCN is separate and
     both have to allow the traffic.

Then: bash deploy/deploy.sh
NEXT
