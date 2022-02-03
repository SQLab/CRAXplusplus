#!/usr/bin/env bash
# Copyright 2021-2022 Software Quality Laboratory, NYCU.

if [ $# -lt 1 ]; then
  echo "usage: $0 <target>"
  exit 0
fi

ln -sf "$HOME/s2e/source/CRAXplusplus/examples/$1/$1" target
ln -sf "$HOME/s2e/source/CRAXplusplus/examples/$1/poc" poc
