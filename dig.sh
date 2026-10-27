#!/usr/bin/env bash

domain="tesla.com"

for type in \
    A AAAA CNAME MX NS SOA TXT \
    CAA DNSKEY DS NSEC NSEC3 \
    HTTPS SVCB SRV TLSA SSHFP \
    PTR
do
    printf '\n\n========== %s ==========\n' "$type"
    dig "$domain" "$type" \
        +dnssec +multiline +comments +stats
done
