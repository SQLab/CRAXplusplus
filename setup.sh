#!/usr/bin/env bash
# Copyright 2021-2022 Software Quality Laboratory, NYCU.
#
# After building S2E, run this script to set up CRAX++.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

S2E_ROOT="$HOME/s2e"
S2E_SRC="$S2E_ROOT/source/s2e"
CRAX_ROOT="$S2E_ROOT/source/CRAXplusplus"
CRAX_SRC="$CRAX_ROOT/src"

function check_dir_exists() {
    if [ ! -d "$1" ]; then
        echo -e "${RED}[!] Please $2 first."
        echo -e "    Reason: $1 directory not found.${RESET}"
        exit 1
    fi
}

function install_crax_config_for_project() {
    # $1: project name (e.g. sym_stdin)
    ln -sfv "$CRAX_ROOT"/proxies/"$1"/s2e-config.template.lua \
            "$S2E_ROOT"/projects/"$1"/s2e-config.template.lua
}

function install_crax_scripts_for_project() {
    # $1: project name (e.g. sym_stdin)
    ln -sfv "$CRAX_ROOT"/proxies/"$1"/bootstrap.sh \
            "$S2E_ROOT"/projects/"$1"/bootstrap.sh

    ln -sfv "$CRAX_ROOT"/scripts/launch-crax.sh \
            "$S2E_ROOT"/projects/"$1"/launch-crax.sh

    ln -sfv "$CRAX_ROOT"/scripts/set-target.sh \
            "$S2E_ROOT"/projects/"$1"/set-target.sh
}

function install_libc_and_ld_for_project() {
    # $1: project name (e.g. sym_stdin)
    ln -sfv "$CRAX_ROOT/examples/libc-2.24.so" \
            "$S2E_ROOT/projects/$1/libc-2.24.so"

    ln -sfv "$CRAX_ROOT/examples/ld-2.24.so" \
            "$S2E_ROOT/projects/$1/ld-2.24.so"
}

function prepare_proxy() {
    # $1: project name (e.g. sym_stdin)
    if [ -d "$S2E_ROOT"/projects/$1 ]; then
        echo -e "[*] Installing config and scripts for $1..."
        install_crax_config_for_project "$1"
        install_crax_scripts_for_project "$1"
        install_libc_and_ld_for_project "$1"
    else
        echo -e "${YELLOW}[!] Skipping $1 (not found)${RESET}"
    fi
}



if [ "`pwd`" != $CRAX_ROOT ]; then
    echo -e "${RED}[!] Please run this script at $CRAX_ROOT.${RESET}"
    exit 1
fi

check_dir_exists "$S2E_SRC" "Please build S2E first"


echo -e '[*] Copying and applying patches to s2e source tree...'
cp "$CRAX_ROOT"/patches/*.patch "$S2E_SRC"
cd "$S2E_SRC" && {
    git apply *.patch >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}[!] Warning: failed to apply patch. You may ignore this message.${RESET}"
    fi
}


echo -e "[*] Copying CRAXplusplus source tree..."
S2E_CRAX_SRC="$S2E_SRC"/libs2eplugins/src/s2e/Plugins/CRAX
if [ -e "$S2E_CRAX_SRC" ]; then
    rm -rf "$S2E_CRAX_SRC"
fi
cp -ar "$CRAX_SRC" "$S2E_SRC"/libs2eplugins/src/s2e/Plugins/CRAX


prepare_proxy sym_arg
prepare_proxy sym_env
prepare_proxy sym_file
prepare_proxy sym_socket
prepare_proxy sym_stdin

echo -e "${GREEN}[*] Success! Now you can run 's2e build' again.${RESET}"
