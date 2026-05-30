## Vendored OpenAPI schemas for Fuzzball

OpenAPI schemas for Fuzzball for every Major.Minor version are vendored in
this repository to allow builds against multiple versions of Fuzzball.

Generated schemas can be obtained from a Fuzzball instance with

```sh
## v3 schema; using a CIQ Fuzzball deployment as an example
curl https://api.stable.fuzzball.ciq.dev/v3/schema
```
