# Changelog Fragments

This directory stores changelog fragment files before release folding into `CHANGELOG.md`.

## Fragment Naming

Fragments must end with `.md` (e.g. `issue-123.md`, `add-feature.md`). Hidden files or `.gitkeep` are ignored.

## Fragment Format

Each fragment file must specify a type header and one or more bullet entries.
Allowed types:
- `### Added`
- `### Changed`
- `### Fixed`
- `### Security`

Alternatively, the header can be lower-case or capitalized (e.g. `### added`, `### fixed`).

Example:
```markdown
### Added
- Added circuit-versioned proof envelope for silent witness v2.
```
