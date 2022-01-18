#!/usr/bin/env bash
# Copyright 2021-2022 Software Quality Laboratory, NYCU.

function usage() {
    echo "CRAXplusplus, software CRash analysis for Automatic eXploit generation."
    echo "Copyright (c) 2021-2022 Software Quality Laboratory, NYCU"
    echo ""
    echo "usage: $0 [option]"
    echo "-c, --canary          - The canary value used during exploit time constraint solving."
    echo "-e, --elf-base        - The elf_base value used during exploit time constraint solving."
    echo "-s, --state-info-list - The I/O states info (define it to skip leak detection/verification)."
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


canary="0"
elf_base="0"
state_info_list="\"\""

# Generate s2e-config.lua from s2e-config.template.lua,
function generate_s2e_config() {
    sed -e "s/__CANARY__/$canary/g" \
        -e "s/__ELF_BASE__/$elf_base/g" \
        -e "s/__STATE_INFO_LIST__/$state_info_list/g" \
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
        -s|--state-info-list)
            state_info_list="\"$2\""
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
