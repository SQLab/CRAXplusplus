#!/usr/bin/env bash
# Copyright 2021-2022 Software Quality Laboratory, NYCU.

"$HOME/s2e/build/qemu-release/x86_64-softmmu/qemu-system-x86_64" \
  -drive file="$HOME/s2e/images/debian-9.2.1-x86_64/image.raw.s2e",format=raw \
  -k en-us \
  -monitor null \
  -m 256M \
  -serial stdio
