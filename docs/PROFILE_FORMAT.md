# User profile files

`sandy run --profile-file PATH -- COMMAND...` loads exactly one explicit JSON
document for that invocation. Sandy never searches for profile files and does
not support directories, includes, URLs, or fallback loading.

The selected document is trusted security configuration and can add host
filesystem or executable authority. The operator must control and trust it. Do
not keep it in a location the target can modify between runs.

The document extends one selectable built-in profile. It is additive: the file
may add typed filesystem grants, executable grants, and terminal filesystem
denials, but it cannot remove or replace the base profile's grants,
protections, or hook behavior.

## Version 1

```json
{
  "schema_version": 1,
  "name": "project-session",
  "extends": "codex",
  "grants": [
    {
      "path": "/Users/example/src/project",
      "access": "read_write",
      "scope": "subtree"
    },
    {
      "path": "~/.cache/project",
      "access": "read",
      "scope": "subtree"
    }
  ],
  "executable_grants": [
    {
      "path": "/Users/example/src/project/target",
      "scope": "subtree"
    }
  ],
  "deny_subtrees": [
    "~/src/project/private"
  ],
  "deny_write_exact": [
    "~/src/project/settings.json"
  ]
}
```

`schema_version`, `name`, and `extends` are required. `extends` names exactly
one selectable built-in profile. A user profile name must not collide with any
built-in profile name.

`grants` accepts only `path`, `access`, and `scope`:

- `access` is `read` or `read_write`.
- `scope` is `exact` or `subtree`.

`executable_grants` accepts only `path` and `scope`. It allows native executable
mapping and launch from an exact path or subtree. It does not grant ordinary
file reads or writes. Likewise, `grants` never adds executable authority. A
path that needs both capabilities must appear explicitly in both sections.

Every file and executable path must be absolute or start with `~/`, and must
exist when Sandy prepares the launch.

`deny_subtrees` denies reads, writes, executable mapping, and launch at the
named path and below it. `deny_write_exact` denies writes to exactly the
named entry while retaining any separately granted read access. Denials are
terminal and override broader grants. Sandy preserves both the safe lexical
spelling and the canonical target of a protection. If the final entry does not
yet exist, Sandy preserves the lexical spelling and resolves its nearest
existing ancestor rather than silently omitting the rule. An unsafe resolution
failure is fatal. Each denial section accepts at most 508 entries. This leaves
room for lexical/canonical expansion, inherited protections, and protection of
the profile source itself within the final policy bound.

Unknown fields are rejected. Version 1 does not support optional grants,
automatic detection, abstract profiles, multiple or user-to-user inheritance,
hook sources, network policy, commands, providers, credentials, raw native
policy, or extension fields.

Path-resolution failures identify the document section and original array
position without echoing the profile-supplied path. Profile and base names may
appear in structural schema errors. Direct command-line path options retain
their existing path-oriented diagnostics.

## Loading and source protection

The source must be an existing regular file containing strict UTF-8 JSON and
must fit Sandy's input bound. Sandy resolves its absolute lexical path and
canonical target before opening the canonical path, then adds terminal subtree
denials for both path spellings to the target policy. An adjacent file is not
denied merely because it shares the same directory.

These pathname checks do not pin an inode, cover hard-link aliases, or remove
the documented replacement race between trusted preparation and target use. A
same-user process outside the sandbox can still replace filesystem entries
during that interval. The current session's source denial does not establish
the file's provenance and cannot protect earlier or future launches.

Dry-run schema version 5 reports the user-visible profile name, `source` set to
`user_file`, and the selected `base`. It does not place the profile-file path or
document contents in profile metadata. The complete dry-run policy necessarily
contains policy paths, including source-path denials; treat dry-run output as
sensitive diagnostic data.
