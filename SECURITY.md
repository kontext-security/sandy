# Security policy

Sandy is experimental security software. Version `0.1.x` has not completed an
independent audit and uses a private, deprecated macOS Seatbelt interface.

Please report vulnerabilities privately through GitHub's security advisory
flow for `kontext-security/sandy`. Do not open a public issue for an unpatched
vulnerability.

Reports should include the Sandy version and commit, macOS version and
architecture, the resolved command shape without secrets, reproduction steps,
and the expected versus observed boundary. Never include credentials, tokens,
private policy contents, or customer data.

User profile files are untrusted bytes for parsing but trusted security
configuration: they can add host filesystem or executable authority. Operators
must control and trust the file they select and should not store it where the
target can modify it between runs. Reports may identify the schema field
involved, but must not paste private profile contents or dry-run policy output. Sandy bounds
and strictly parses an explicitly selected regular UTF-8 file; it never
searches for profile files or falls back after a load failure.

Security-sensitive changes require a positive compatibility test and a
negative test proving adjacent access remains denied. Live Seatbelt tests must
run in sacrificial subprocesses because applying the sandbox is irreversible.
