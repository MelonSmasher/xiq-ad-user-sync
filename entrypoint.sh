#! /usr/bin/env bash

while true; do
    # shellcheck disable=SC1091
    source venv/bin/activate && python XIQ-AD-PPSK-Sync.py && sleep "${SYNC_INTERVAL_SEC}"
done
