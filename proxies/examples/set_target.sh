#!/usr/bin/env bash

if [ $# -lt 1 ]; then
  echo "usage: $0 <target>"
  exit 0
fi

rm target poc
ln -s "../../examples/$1/$1" target
ln -s "../../examples/$1/poc" poc
