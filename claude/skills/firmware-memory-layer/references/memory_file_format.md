# Firmware Memory File Format

Memory files are Markdown with YAML-like frontmatter. Required frontmatter keys are:

- `memory_schema_version`
- `memory_type`
- `title`
- `status`
- `tags`
- `applies_to`
- `evidence`
- `artifact_sensitivity`

Allowed `memory_type` values are `product`, `service`, and `tool`.

Allowed `status` values are `draft`, `active`, `deprecated`, and `needs_revalidation`.

Allowed `artifact_sensitivity` values are `public_reference`, `local_metadata`, and `local_sensitive`. `secret_material` and `firmware_proprietary` are not allowed in memory files.

Required headings are:

- `## Use When`
- `## Durable Pattern`
- `## Evidence`
- `## Limits`
- `## Safety`
