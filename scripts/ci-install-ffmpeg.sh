#!/usr/bin/env bash
set -euo pipefail

# GitHub-hosted Ubuntu runners pin azure.archive.ubuntu.com. That mirror
# often hangs until timeout even when archive.ubuntu.com is reachable, so
# retries of apt-get update still fail. Rewrite the Azure hostname first.
rewrite_azure_apt_mirrors() {
	local path
	shopt -s nullglob
	for path in \
		/etc/apt/sources.list \
		/etc/apt/apt-mirrors.txt \
		/etc/apt/mirrors.txt \
		/etc/apt/sources.list.d/*.list \
		/etc/apt/sources.list.d/*.sources \
		/etc/apt/mirrors/*.list; do
		[[ -f "$path" ]] || continue
		if grep -q 'azure.archive.ubuntu.com' "$path"; then
			sudo sed -i 's/azure\.archive\.ubuntu.com/archive.ubuntu.com/g' "$path"
			echo "rewrote azure apt mirror in ${path}"
		fi
	done
}

rewrite_azure_apt_mirrors

# Retry apt-get update if a remaining mirror still stalls.
apt_opts=(
	-o Acquire::Retries=3
	-o Acquire::http::Timeout=20
	-o Acquire::https::Timeout=20
	-o DPkg::Lock::Timeout=30
)

attempt=1
max_attempts=3
until sudo timeout 180s apt-get "${apt_opts[@]}" update; do
	if ((attempt >= max_attempts)); then
		echo "error: apt-get update failed after ${max_attempts} attempts" >&2
		exit 1
	fi
	attempt=$((attempt + 1))
	sleep 10
done

sudo env DEBIAN_FRONTEND=noninteractive timeout 900s apt-get \
	"${apt_opts[@]}" \
	install -y --no-install-recommends ffmpeg
