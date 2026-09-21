# KeyTrace

KeyTrace is a context and flow aware secret detection research project that uses static analysis and large language models to improve the detection of exposed credentials in source code.

The goal is to go beyond traditional secret scanners that mainly rely on regex patterns, entropy, and nearby textual context. KeyTrace analyzes how potential credentials are created, propagated, and used throughout a program.

## Project Goals

KeyTrace aims to:

- Detect potential secrets in source code
- Trace how candidate credentials move through variables and functions
- Identify whether values reach security-sensitive operations
- Use source-code context and program flow to reduce false positives
- Use an LLM to infer the intended use of a credential
- Compare the approach against traditional secret scanners such as Gitleaks and TruffleHog
