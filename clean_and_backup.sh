#!/bin/bash
mkdir -p backups/$(date +%Y%m%d_%H%M%S)
cp -r Sources Package.swift docs EternumSentinel backups/$(date +%Y%m%d_%H%M%S)/ 2>/dev/null || true
rm -rf .build .swiftpm
echo "Backup complete, artifacts purged."
