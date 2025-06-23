#!/bin/bash

# Get the current working directory (where this script is run)
WORKDIR="$(pwd)"

# Escape for AppleScript
ESCAPED_DIR="${WORKDIR//\"/\\\"}"

osascript <<EOF
tell application "Terminal"
	activate

	-- Open first window and run Rust program 1
	set win1 to do script "cd \"$ESCAPED_DIR\";cargo run --bin homomorphic_enc"
	delay 0.5
	set bounds of front window to {0, 0, 800, 600}

	-- Open second window and run Rust program 2
	set win2 to do script "cd \"$ESCAPED_DIR\"; cargo run --bin client" in (do script "")
	delay 0.5
	set bounds of front window to {810, 0, 1610, 600}
end tell
EOF
