# Changelog

## v12 - Campaign Clustering
Offline hostname-similarity and path-prefix grouping of URL indicators, with JSON export. Findings are investigation leads, not verdicts.

## v11 - Content Signature Scanner
Regex signatures (script, macro, obfuscation, persistence) over the first 2 MiB of uploaded bytes. Reports ID, severity, offsets, evidence snippet and SHA-256.

## v10 - File Triage
SHA-256, size, magic-byte type hints, entropy of the first MiB, double-extension and extension/signature mismatch warnings. Files are never executed.

## v9 - Email Header Analyzer
From/Reply-To and From/Return-Path mismatches, SPF/DKIM/DMARC parsing, Received-hop count, JSON export.

## v8 - Rule-based Hunting
Editable literal-string rules (ID, severity, category). No regex or code execution. Input capped at 1,000,000 characters.

## v7 - Hunting and reports
Search and filter scan history with CSV export. Print-ready HTML incident reports with escaped user content.

## v6 - Incident Casebook
Local cases with severity, notes, indicators, lifecycle status and timeline. JSON/CSV export.

## v5 - Clustering and STIX
Suffix-based hostname clustering and STIX 2.1 URL-indicator export.

## v4 - IOC utilities
URL extraction from pasted text (including hxxp / [.] notation), URL fingerprints, CSV export.

## v3 - IOC Toolkit
URL comparison, structural facts, defanged output, deduplicated IOC bundle.

## v2 - URL Structure Lab
Explainable 0-100 heuristic score (HTTP, IP hosts, punycode, shorteners, odd ports, long URLs, sensitive words).

## v1 - Foundation
Google Safe Browsing and VirusTotal read-only lookups, single/batch CSV scan (max 500 rows), SQLite history, allow/block lists.
