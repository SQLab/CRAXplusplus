#!/usr/bin/env bash
# Copyright 2021-2022 Software Quality Laboratory, NYCU.

function usage() {
    echo "usage: $0 [-s|--staging] <target>"
    echo "examples:"
    echo "$0 unexploitable"
    echo "$0 --staging b64"
}

function create_symlinks() {
    # $1: directory name (either examples or examples-staging)
    # $2: target binary name (e.g., unexploitable)
    ln -sfv "$HOME/s2e/source/CRAXplusplus/$1/$2/$2" "target"
    ln -sfv "$HOME/s2e/source/CRAXplusplus/$1/$2/poc" "poc"
}


if [ $# -lt 1 ]; then
    usage
    exit 0
fi

# Parse command-line options
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -s|--staging)
            create_symlinks "examples-staging" $2
            exit 0
            ;;
        -*|--*)
            echo "Unknown option: $1"
            exit 1
            ;;
        *)
            echo $1
            create_symlinks "examples" $1
            exit 0
            ;;
    esac
done
