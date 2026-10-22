# AI usage: dsc26-cyb-w02

## Tools

I used Claude Code (Claude Sonnet 5.5) for most of the implementation and testing of this task.

- `tmcheck/core.py` and `tmcheck/__main__.py` were implemented with Claude based on the rules and requirements in the starter repository.
- `tests/test_edge_cases.py` was written with Claude to cover the different validation, STRIDE, policy, coverage, and ranking rules, including cases related to the hidden-test areas H01 to H14.
- `models/rawaj_scoring.yaml` was updated with the required additional threats (T27 to T38), and the protocol of flow `f08` was changed from `postgres` to `tls`. The existing starter zones, elements, flows, and threats were kept.
- This `AI_USAGE.md` file was also drafted with Claude. I reviewed it and kept the parts that describe what actually happened during the implementation.

Claude also ran the test suite, ran the checker against the model, and compared the final model with the starter version to make sure the original starter items were preserved. I have not manually reviewed every single threat and rule line by line yet.

## What AI got wrong

There were a few issues during development:

- Some of Claude's first policy tests failed because the test model did not contain an `I` threat for the PII store. The checker correctly reported the policy finding, so the test setup was fixed instead of changing the checker.
- Two early ranking tests used scores such as 14 and 7 as boundaries. Those values cannot be produced by multiplying two integer scores from 1 to 5, so the tests were changed to use realistic boundaries such as 15, 12, 8, and 6.
- In an earlier version of the project, before the official starter repository was available, one ranking test contained an invalid score expression. That version was not kept in the final repository.
- To make sure the tests were actually checking the implementation, several bugs were intentionally introduced into `core.py` and tested one at a time. The test suite caught the introduced issues, including incorrect score handling, protocol comparison, whitespace validation, STRIDE ordering, natural ID sorting, ranking boundaries, coverage status handling, flow direction handling, invalid categories, and ID namespace handling.

## In my own words

1. Why does a data store have no Spoofing threats in STRIDE per element, and where does that threat go instead?

A data store does not have a Spoofing threat because Spoofing is about pretending to be an identity, while a data store is mainly a place where data is stored. If an attacker can pretend to be someone when accessing the store, that is usually modeled on the process, user, or access flow connected to the data store.

2. Which of the new threats would you fix first, and why?

I would prioritize the threat related to exposing PII over a plaintext connection. I would fix it first because customer information is sensitive, and exposing it while crossing a trust boundary could have a serious impact even if the rest of the system is working normally.
