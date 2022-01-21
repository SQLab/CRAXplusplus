#!/usr/bin/env bash
# Copyright 2021-2022 Software Quality Laboratory, NYCU.

CANARY="0"
ELF_BASE="0"
STATE_INFO_LIST="\"\""

function usage() {
    echo "CRAXplusplus, software CRash analysis for Automatic eXploit generation."
    echo "Copyright (c) 2021-2022 Software Quality Laboratory, NYCU"
    echo ""
    echo "usage: $0 [option]"
    echo "-c, --canary          - The canary value used during exploit time constraint solving."
    echo "-e, --elf-base        - The elf_base value used during exploit time constraint solving."
    echo "-s, --state-info-list - The I/O states info (define it to skip leak detection/verification)."
}

# Generate s2e-config.lua from s2e-config.template.lua,
function generate_s2e_config() {
    sed -e "s/__CANARY__/$CANARY/g" \
        -e "s/__ELF_BASE__/$ELF_BASE/g" \
        -e "s/__STATE_INFO_LIST__/$STATE_INFO_LIST/g" \
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
            CANARY="$2"
            shift
            shift
            ;;
        -e|--elf-base)
            ELF_BASE="$2"
            shift
            shift
            ;;
        -s|--state-info-list)
            STATE_INFO_LIST="\"$2\""
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
exec ./launch-s2e.sh
