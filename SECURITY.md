# Security policy

## Supported versions

Security fixes are provided for the latest revision of the `main` branch until
the project begins publishing versioned releases. After releases begin, this
section will list the supported release lines explicitly.

## Reporting a vulnerability

Do not open a public issue or discussion for a suspected vulnerability. Use
the repository's **Security** tab and select **Report a vulnerability** to open
a private GitHub security advisory. Include:

- the affected commit or version;
- the prerequisites and reproducible steps;
- the expected and observed behavior;
- the potential impact;
- a minimal proof of concept with all credentials and operational data removed;
- any suggested mitigation, if available.

If private vulnerability reporting is not yet enabled, contact the repository
owner privately and ask them to enable it before sharing technical details.
Never send active CONNX credentials, bearer tokens, Azure keys, `.env` files,
database files, customer names, or unredacted job history.

The maintainers should acknowledge a complete report within five business days,
provide status updates during remediation, coordinate disclosure with the
reporter, and publish a GitHub security advisory when appropriate. Timelines
depend on severity and the availability of a safe fix.

## Security expectations for deployments

This project is an operator-facing dashboard, not an internet security
boundary. Follow [`DEPLOYMENT.md`](DEPLOYMENT.md), restrict network access,
terminate HTTPS at a trusted proxy, use least-privilege CONNX and Azure
identities, mount secrets from a managed secret store, and protect the SQLite
database because it temporarily contains session tokens and queued analysis
inputs.
