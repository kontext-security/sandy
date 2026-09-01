# CLI policy files

`sandy run --policy-file PATH -- COMMAND...` loads one complete
caller-controlled policy document for that invocation. The JSON shape is the
same strict, bounded, versioned `SandboxPolicy` document accepted by the Rust
API.

Sandy never searches for policy files and does not support directories,
includes, URLs, interpolation, inheritance, or fallback loading. The selected
file is trusted security configuration and can grant access to host resources.
The operator must control it.

```json
{
  "schema_version": 1,
  "network": "block_all",
  "allow_subprocesses": true,
  "grants": [
    {
      "path": ".",
      "access": "read_write",
      "scope": "subtree"
    }
  ],
  "executable_grants": [
    {
      "path": "./tools",
      "scope": "subtree"
    }
  ],
  "deny_subtrees": ["./credentials"],
  "deny_write_exact": ["./settings.json"]
}
```

The CLI requires `allow_subprocesses` to be `true`: its bootstrap must replace
itself with the target, and the resulting process sandbox is inherited by
later descendants. Use `sandy::apply` when a Rust application needs a
current-process policy that disables further execution.

## Composition boundary

The document completely replaces the selected agent preset's policy. Sandy
does not add the agent's state-directory grants, sensitive-path denials, or
automatically discovered integrations.

The CLI still adds its fixed, typed launcher requirements:

- the platform runtime and loader baseline;
- read/write and executable access to the working directory;
- the resolved target, its executable parent, and the private session;
- a public CA bundle when networking is allowed; and
- an explicitly required runtime-control integration.

Every addition appears in `--dry-run` output. An authored denial that conflicts
with a required launcher capability fails before target execution. The CLI
never retries with a weaker policy.

Because the document is complete caller policy, `--policy-file` conflicts with
agent selection, the legacy profile-file option, `--read`, `--read-write`,
`--execute`, `--block-net`, and the collector shortcut. Explicit `--kontext`
or `--numbat` remains available because selecting either option is itself an
explicit request for its verified capabilities.

## Paths and source protection

Relative paths are resolved against the launch working-directory snapshot.
Filesystem and executable grants must exist. Denials preserve their lexical
spelling and canonical target; a missing denial leaf is resolved through its
nearest existing ancestor so a future sensitive entry does not become
unprotected.

The source must be an existing regular file within Sandy's 64-KiB document
bound. Sandy opens the canonical path selected during trusted preparation and
adds terminal subtree denials for both its absolute lexical and canonical
spellings. These pathname protections do not authenticate the file, cover
hard-link aliases, or eliminate replacement races with another same-user
process.

Dry-run schema version 7 reports `policy_source.kind` as `policy_file` without
including the source path or document contents. The complete dry-run policy
contains resolved capability paths and must still be treated as sensitive
diagnostic data.
