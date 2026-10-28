# Security policy

## Supported version

Security fixes are made on the default branch.

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Use GitHub's private security advisory reporting for this repository, or contact the repository owner privately. Include a minimal reproduction and avoid sending credentials, Management addresses, firewall output, or customer data.

## Deployment expectations

This dashboard accepts Check Point Management credentials to create an in-memory API session. Operators must deploy it behind HTTPS and strong access controls, restrict it to trusted networks, and use a least-privilege read-only Check Point account. It is not designed for unauthenticated public exposure.
