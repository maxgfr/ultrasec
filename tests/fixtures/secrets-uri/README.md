Fixture for issue #10 (defect 3): secret scanning inverted on an infra repo.

`env/*/values.yaml` carry the real leak — a literal password in a connection
string whose other components are templated. `sealed/*` are ciphertext by
design and must be de-prioritized, not headlined.
