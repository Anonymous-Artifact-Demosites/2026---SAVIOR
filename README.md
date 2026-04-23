# SAVIOR Artifact

This repository contains the artifact for SAVIOR.

## Overview

SAVIOR is a system for analyzing account-management vulnerabilities in integrated OAuth relying parties.

The repository includes:

- `savior/` - source code and example artifacts
- `savior/SAVIOR_GUIDE.md` -  detailed technical guide aligned with §5 of the paper
- `previous_release/` - previously released files

## Repository Layout

- `savior/browser_interactor/` - browser-facing execution layer
- `savior/semantic_navigator/` - prompt construction and task orchestration
- `savior/state_auditor/` - parsing, invariant evaluation, cross-checking, and report generation
- `savior/runner/` - batch execution logic
- `savior/configs/` - invariant definitions
- `savior/example_runs/` - example artifacts with redacted test-account details

## Notes

This repository is intended for artifact review and code inspection.
