# Tests

`pe_api.test.js` loads `db/PE/_init` in a small PE mock and verifies:

- cached section entropy and named/indexed section lookup;
- cached import-table entries and library/function lookup;
- all/any/none/not composable signature conditions, including entropy, import,
  limit and byte-signature predicates;
- positive and negative results for the PEzor and generic entropy/import rules.

The binary fixtures are described in [`samples/README.md`](samples/README.md).

```sh
node tests/pe_api.test.js
```
