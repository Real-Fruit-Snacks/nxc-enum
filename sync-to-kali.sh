#!/bin/bash
# Sync nxc-enum to Kali for testing
# Only copies files needed to run and test the application

SRC="/mnt/hgfs/Notes/nxc-enum"
DEST="/root/tools/nxc_enum"

rsync -av --delete \
    --exclude='.git/' \
    --exclude='__pycache__/' \
    --exclude='*.pyc' \
    --exclude='*.pyo' \
    --exclude='.pytest_cache/' \
    --exclude='*.egg-info/' \
    --exclude='dist/' \
    --exclude='build/' \
    --exclude='.github/' \
    --exclude='*.md' \
    --exclude='LICENSE' \
    --exclude='.pre-commit-config.yaml' \
    --exclude='.gitignore' \
    --exclude='.vscode/' \
    --exclude='.idea/' \
    --exclude='Test_*.txt' \
    "$SRC/" "$DEST/"

echo ""
echo "Synced to $DEST"
