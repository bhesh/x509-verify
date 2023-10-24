#!/bin/bash

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

for f in "$SRC_DIR"/*-key.pem; do
    key_file="$(basename "$f")"
    digest="$(echo "$key_file" | sed -e 's/.*-sha/sha/' -e 's/-.*//')"
    subj="/CN=${key_file/-key.pem/}"
    req_file="${key_file/-key/-req}"
    crt_file="${key_file/-key/-crt}"

    echo "Generating request for $subj"
    openssl req -new -$digest -key "$SRC_DIR/$key_file" -subj "$subj" -out "$SRC_DIR/$req_file"

    echo "Generating public certificate for $subj"
    openssl req -new -x509 -days 1095 -$digest -key "$SRC_DIR/$key_file" -subj "$subj" -out "$SRC_DIR/$crt_file"
done
