#!/usr/bin/env bash
# Copyright 2021-2022 Software Quality Laboratory, NYCU.
#
# After building S2E, run this script to set up CRAX++.

S2E_ROOT="$HOME/s2e"
S2E_SRC="$S2E_ROOT/source/s2e"

CRAX_ROOT="$S2E_ROOT/source/CRAXplusplus"
CRAX_SRC="$CRAX_ROOT/src"

function check_dir_exists() {
    if [ ! -d "$1" ]; then
        echo "[!] Please $2 first."
        echo "    Reason: $1 directory not found."
        exit 1
    fi
}

function relink() {
    # $1: dst
    # $2: src
    if [ -f "$2" ]; then
        rm -v "$2"
    fi

    if [ -d "$2" ]; then
        rm -rfv "$2"
    fi

    ln -sfv "$1" "$2"
}

function install_crax_config_for_project() {
    # $1: project name (e.g. sym_stdin)
    relink "$CRAX_ROOT"/config/s2e-config.template.lua \
           "$S2E_ROOT"/projects/"$1"/s2e-config.template.lua
}

function install_crax_scripts_for_project() {
    # $1: project name (e.g. sym_stdin)
    relink "$CRAX_ROOT"/scripts/bootstrap.sh \
           "$S2E_ROOT"/projects/"$1"/bootstrap.sh

    relink "$CRAX_ROOT"/scripts/launch-crax.sh \
           "$S2E_ROOT"/projects/"$1"/launch-crax.sh

    relink "$CRAX_ROOT"/scripts/set-target.sh \
           "$S2E_ROOT"/projects/"$1"/set-target.sh
}



if [ "`pwd`" != $CRAX_ROOT ]; then
    echo "[!] Please run this script at $CRAX_ROOT."
    exit 1
fi

check_dir_exists "$S2E_SRC" "Please build S2E first"


echo '[*] Copying and applying patches to s2e source tree...'
cp "$CRAX_ROOT"/patches/*.patch "$S2E_SRC"
cd "$S2E_SRC" && {
    git apply *.patch #>/dev/null 2>&1
}
relink "$CRAX_ROOT"/patches/libs2eplugins/src/CMakeLists.txt \
       "$S2E_SRC"/libs2eplugins/src/CMakeLists.txt


echo '[*] Copying CRAXplusplus source tree...'
S2E_CRAX_SRC="$S2E_SRC"/libs2eplugins/src/s2e/Plugins/CRAX
if [ -e "$S2E_CRAX_SRC" ]; then
    rm -rfv "$S2E_CRAX_SRC"
fi
cp -arv "$CRAX_SRC" "$S2E_SRC"/libs2eplugins/src/s2e/Plugins/CRAX


if [ -d "$S2E_ROOT"/projects/sym_stdin ]; then
    echo '[*] Installing config and scripts for sym_stdin...'
    install_crax_config_for_project "sym_stdin"
    install_crax_scripts_for_project "sym_stdin"
else
    echo '[!] Skipping sym_stdin (not found)'
fi


if [ -d "$S2E_ROOT"/projects/sym_file ]; then
    echo '[*] Installing config and scripts for sym_file...'
    install_crax_config_for_project "sym_file"
    install_crax_scripts_for_project "sym_file"
else
    echo '[!] Skipping sym_stdin (not found)'
fi

echo "[*] Success! Now you can run 's2e build' again."
