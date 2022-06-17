#!/bin/bash

#script to add all bash dependencies

#ask for sudo
[ "$UID" -eq 0 ] || exec sudo "$0" "$@"
wget https://github.com/mikefarah/yq/releases/download/v4.25.2/yq_linux_amd64 -O /usr/bin/yq && chmod +x /usr/bin/yq