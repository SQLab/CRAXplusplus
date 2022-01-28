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
    ln -sfv "$CRAX_ROOT"/config/s2e-config.template.lua \
            "$S2E_ROOT"/projects/"$1"/s2e-config.template.lua
}

function install_crax_scripts_for_project() {
    # $1: project name (e.g. sym_stdin)
    ln -sfv "$CRAX_ROOT"/scripts/bootstrap.sh \
            "$S2E_ROOT"/projects/"$1"/bootstrap.sh

    ln -sfv "$CRAX_ROOT"/scripts/launch-crax.sh \
            "$S2E_ROOT"/projects/"$1"/launch-crax.sh

    ln -sfv "$CRAX_ROOT"/scripts/set-target.sh \
            "$S2E_ROOT"/projects/"$1"/set-target.sh
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
ln -sfv "$CRAX_ROOT"/patches/libs2eplugins/src/CMakeLists.txt \
        "$S2E_SRC"/libs2eplugins/src/CMakeLists.txt


echo -e "[*] Copying CRAXplusplus source tree..."
S2E_CRAX_SRC="$S2E_SRC"/libs2eplugins/src/s2e/Plugins/CRAX
if [ -e "$S2E_CRAX_SRC" ]; then
    rm -rf "$S2E_CRAX_SRC"
fi
cp -ar "$CRAX_SRC" "$S2E_SRC"/libs2eplugins/src/s2e/Plugins/CRAX


if [ -d "$S2E_ROOT"/projects/sym_stdin ]; then
    echo -e "[*] Installing config and scripts for sym_stdin..."
    install_crax_config_for_project "sym_stdin"
    install_crax_scripts_for_project "sym_stdin"
else
    echo -e "${YELLOW}[!] Skipping sym_stdin (not found)${RESET}"
fi


if [ -d "$S2E_ROOT"/projects/sym_file ]; then
    echo -e "[*] Installing config and scripts for sym_file..."
    install_crax_config_for_project "sym_file"
    install_crax_scripts_for_project "sym_file"
else
    echo -e "${YELLOW}[!] Skipping sym_file (not found)${RESET}"
fi

echo -e "${GREEN}[*] Success! Now you can run 's2e build' again.${RESET}"