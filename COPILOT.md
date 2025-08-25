# Copilot Playbook: How to work in this repo

Paste these prompts into Copilot Chat as you iterate.

## 1) Testing and coverage
- “Write additional unit tests for edge cases in the public API. Keep tests deterministic and avoid external network calls.”
- “Generate property-based tests for canonical JSON stability.”

## 2) Security & correctness
- “Review all signature and ID derivation functions. Propose hardening tweaks and update docstrings with exact formats.”
- “Add input validation and precise error types for bad payloads or missing fields.”

## 3) Examples & docs
- “Create an `examples/` script that demonstrates end-to-end usage, and document each step inline.”
- “Improve README ‘Quick start’ and add a FAQ for common errors.”

## 4) Packaging & releases
- “Add a CONTRIBUTING.md and a simple semantic-release style CHANGELOG.md.”
- “Confirm pyproject metadata, license, and classifiers are correct for PyPI.”

## 5) CI polish
- “Extend the publish workflow to run `pytest` and fail on coverage < 90%.
  If coverage fails, block release and post an artifact with coverage HTML.”
