#!/usr/bin/env bash
# Copyright 2021-2022 Software Quality Laboratory, NYCU.

if [ "$1" = "mount" ]; then
  sudo losetup /dev/loop15 ~/s2e/images/debian-9.2.1-x86_64/image.raw.s2e
  sudo kpartx -a /dev/loop15
  sudo mount /dev/mapper/loop15p2 /mnt
  echo "[*] mounted s2e image at /mnt"
elif [ "$1" = "umount" ]; then
  sudo umount /mnt
  sudo kpartx -d /dev/loop15
  sudo losetup -d /dev/loop15
  echo "[*] umounted s2e image."
else
  echo "usage: $0 [mount|umount]"
fi
