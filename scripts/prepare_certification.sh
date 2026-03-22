#!/usr/bin/env bash

# Pure-MLS Certification Preparation Script
# Combines all relevant code into a single digest file for LLM Auditors (Claude/DeepSeek).

OUTPUT_FILE="PURE_MLS_DIGEST.txt"

echo "Creating Pure-MLS Certification Digest..."
> "$OUTPUT_FILE"

append_file() {
	local file=$1
	if [ -f "$file" ]; then
		echo "Appending $file..."
		echo -e "\n\n================================================================" >> "$OUTPUT_FILE"
		echo "FILE: $file" >> "$OUTPUT_FILE"
		echo "================================================================" >> "$OUTPUT_FILE"
		cat "$file" >> "$OUTPUT_FILE"
	fi
}

# Documentation & Configs
append_file "README.md"
append_file "CHANGELOG.md"
append_file "CONTRIBUTING.md"
append_file "pyproject.toml"
append_file ".github/workflows/ci.yml"

# Explicitly exclude CERTIFICATION folder but include other deep markdown files if any
find docs -type f -name "*.md" -not -path "*/CERTIFICATION/*" 2>/dev/null | sort | while read -r line; do
	append_file "$line"
done

# Core Library
find src/pure_mls -type f -name "*.py" | sort | while read -r line; do
	append_file "$line"
done

# End-to-End Tests
find tests -type f -name "*.py" | sort | while read -r line; do
	append_file "$line"
done

echo "Done! The digest is ready at $OUTPUT_FILE."
echo "Total payload: $(wc -l < "$OUTPUT_FILE") lines."
