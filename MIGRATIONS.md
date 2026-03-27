# NetWatch — Schema Migrations

This file tracks all database schema changes introduced after the first public
release. The update installer reads this file to determine which SQL statements
need to be applied when upgrading between versions.

## Format

Each version heading marks the schema changes introduced in that release.
Statements are plain SQL. The installer collects all entries newer than the
installed version and applies them in order (oldest first) before installing
the package zip.

No entries exist before the first public release — there are no users on any
prior version and no migrations to reconstruct.

## Rules (for Claude during development)

- When a session package includes a `run_sql` action, the same SQL goes here
  under the new version heading.
- Entries are append-only — never edit or remove an existing entry.
- Version headings must exactly match the VERSION file format (e.g. `3.4.0`).
- The installer uses `packaging.version` for comparison — headings must be
  valid version strings.

---

<!-- Entries begin below this line. Oldest at bottom, newest at top. -->

## 3.4.31
ALTER TABLE system_settings ADD COLUMN _test_col_2 TEXT DEFAULT NULL

## 3.4.30
ALTER TABLE system_settings ADD COLUMN _test_col_1 TEXT DEFAULT NULL
