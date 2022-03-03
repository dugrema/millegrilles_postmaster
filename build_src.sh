#!/usr/bin/env bash

echo "Build target rust"
cargo b --release --package millegrilles_postmaster --bin millegrilles_postmaster
