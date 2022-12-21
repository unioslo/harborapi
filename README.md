# harborapi

[![PyPI - Version](https://img.shields.io/pypi/v/harborapi.svg)](https://pypi.org/project/harborapi)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/harborapi.svg)](https://pypi.org/project/harborapi)

-----


Python async client for the Harbor REST API v2.0.

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
- [x] replication
- [ ] label
- [x] robot
- [ ] webhookjob
- [ ] icon
- [x] project
- [ ] webhook
- [x] scan
- [ ] member
- [x] ldap
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
- [x] projectMetadata
- [x] auditlog

\*\* `/systeminfo/getcert` NYI
