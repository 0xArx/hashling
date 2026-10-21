#!/bin/sh
# Double-click this file in Finder to install Hashling. It opens Terminal and runs install.sh.
cd "$(dirname "$0")" || exit 1
sh ./install.sh
printf '\nYou can close this window now.\n'
