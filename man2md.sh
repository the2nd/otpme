#!/bin/bash
# man2md.sh - Convert OTPme man pages to Markdown using pandoc
#
# Usage: ./man2md.sh [--output-dir DIR] [--man-dir DIR]
#
# Requires: pandoc

MAN_DIR="$(dirname "$0")/otpme/man"
OUT_DIR="$(dirname "$0")/docs"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --man-dir)   MAN_DIR="$2"; shift 2 ;;
        --output-dir) OUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if ! command -v pandoc &>/dev/null; then
    echo "Error: pandoc not found. Install with: apt install pandoc" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
count=0

for src in "$MAN_DIR"/*.{1,5,7}; do
    [[ -f "$src" ]] || continue
    base=$(basename "$src")
    ext="${base##*.}"
    name="${base%.*}"

    # Section 5 and 7 keep their section number in the filename
    if [[ "$ext" == "5" || "$ext" == "7" ]]; then
        dst="$OUT_DIR/${base}.md"
    else
        dst="$OUT_DIR/${name}.md"
    fi

    pandoc -f man -t gfm "$src" -o "$dst"
    echo "$base -> $(basename "$dst")"
    ((count++))
done

echo "Converted $count man page(s) to $OUT_DIR/"
