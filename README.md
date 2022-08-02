# Harbor API

Python async API wrapper for the Harbor  REST API v2.0.

## Features

- Async API
- Fully typed
- Data validation with [Pydantic](https://pydantic-docs.helpmanual.io/)
- HTTP handled by [HTTPX](https://www.python-httpx.org/)
- Extensive test coverage powered by [Hypothesis](https://hypothesis.works/)

## Installation

```bash
pip install harborapi
```

## Documentation

Documentation is available [here](https://pederhan.github.io/harborapi/)

## Implemented endpoints

<!-- - [ ] Products
- [ ] Chart Repository
- [ ] Label -->
- [x] user
- [x] gc
- [x] scanAll
- [x] configure
- [x] usergroup
- [ ] preheat
- [ ] replication
- [ ] label
- [x] robot
- [ ] webhookjob
- [ ] icon
- [x] project
- [ ] webhook
- [x] scan
- [ ] member
- [ ] ldap
- [x] registry
- [x] search
- [x] artifact
- [ ] immutable
- [ ] retention
- [x] scanner
- [x] systeminfo**
- [x] statistic
- [x] quota
- [x] repository
- [x] ping
- [x] oidc
- [x] SystemCVEAllowlist
- [x] Health
- [ ] robotv1
- [ ] projectMetadata
- [x] auditlog

\*\* `/systeminfo/getcert` NYI
