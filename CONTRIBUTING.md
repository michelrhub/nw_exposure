# Contributing

Thanks for your interest in contributing.

## Contribution Scope

Contributions are welcome for:

- OCI data extraction scripts
- SQL analysis queries
- Documentation and operational guides
- Reliability/performance improvements

## Development Guidelines

- Keep scripts and queries modular and readable.
- Prefer backwards-compatible changes when possible.
- Document new parameters, outputs, and assumptions.
- Add/update docs when behavior changes.

## Pull Request Checklist

- Describe the problem and proposed solution.
- Include test/validation evidence (command output, sample checks).
- Update relevant docs (`README`, `docs/*`).
- Ensure no sensitive data is committed.

## Security and Data Hygiene

- Do not commit OCI credentials, tokens, private keys, or exported JSONL data.
- Redact tenancy-specific sensitive details in examples.

## Reporting Issues

Please include:

- environment details (runtime, auth mode, region scope)
- command used
- observed behavior and expected behavior
- sanitized logs/errors
