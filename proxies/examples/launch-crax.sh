#!/usr/bin/env bash
# Copyright 2021-2022 Software Quality Laboratory, NYCU.

canary="0"
elf_base="0"

function usage() {
    echo "CRAXplusplus, software CRash analysis for Automatic eXploit generation."
    echo "Copyright (c) 2021-2022 Software Quality Laboratory, NYCU"
    echo ""
    echo "usage: $0 [option]"
    echo "-c, --canary    - The canary value used during exploit time constraint solving."
    echo "-e, --elf-base  - The elf_base value used during exploit time constraint solving."
}

# $1 - args array
# $2 - the target argument to match
function has_argument() {
    args=("$@")
    target=${args[${#args[@]}-1]} # extract target argument
    unset 'args[${#args[@]}-1]' # remove last element

    for arg in "${args[@]}"; do
        if [ "$arg" == "$target" ]; then
            return 0
        fi
    done
    return 1
}

# Generate s2e-config.lua from s2e-config.template.lua,
function generate_s2e_config() {
    sed -e "s/CANARY/$canary/g" \
        -e "s/ELF_BASE/$elf_base/g" \
        s2e-config.template.lua > s2e-config.lua
}


# Parse command-line options
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -c|--canary)
            canary="$2"
            shift
            shift
            ;;
        -e|--elf-base)
            elf_base="$2"
            shift
            shift
            ;;
        -*|--*)
            echo "Unknown option: $1"
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

generate_s2e_config
chmod u+x ./s2e-config.lua
./launch-s2e.sh
