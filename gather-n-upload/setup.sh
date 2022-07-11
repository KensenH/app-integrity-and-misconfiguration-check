#!/bin/bash

#ask for sudo
[ "$UID" -eq 0 ] || exec sudo "$0" "$@"

TEMP_DEB="$(mktemp)" &&
wget -O "$TEMP_DEB" 'https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.jammy_amd64.deb' &&
sudo dpkg -i "$TEMP_DEB"
rm -f "$TEMP_DEB"