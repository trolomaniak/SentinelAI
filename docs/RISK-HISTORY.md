# Risk history and trends

Open **Risk** and select the organization or an endpoint. Choose **24 hours**, **7 days**, **30 days**, or **90 days** to see retained measurements for that scope. The chart shows recorded points on a 0–100 scale. The accessible table includes the actual measurement time, displayed and raw scores, policy version and fingerprint, comparison time, observed changes and principal scoring rule IDs. The raw score may exceed 100. The current Risk view separately evaluates the current data.

Core evaluates the same active fleet and scoring rules used by the current Risk view. It stores one actual measurement per six-hour UTC bucket when Core is available. A newly installed Core can capture its current bucket immediately. Core does not recreate past buckets after downtime, a missed attempt, or a clock correction. A measured zero for an organization with no enrolled endpoints describes an empty fleet. A blank period means there are no retained measurements for it.

The organization displayed and raw scores are the largest corresponding endpoint scores. The governing endpoint is selected by uncapped score, with a deterministic identifier tie-break. Historical points for removed endpoints retain their normal expiry. Organization history starts and stops at recorded measurements. Lines would imply values for unobserved intervals, so the graph shows individual points.

## Interpreting changes

A point compares with the immediately preceding recorded measurement for its scope where one exists. The comparison records changes to the scoring policy, the contributing alert set or its status/severity, observation time or age band, confirmation, endpoint context and correlation, when those changes can be established. The organization also records fleet and governing endpoint changes. A changed governing endpoint limits comparison of its individual factors with the previous maximum. A status change reflects what was recorded. An unexplained delta remains unclassified. The top rule IDs show which findings contributed most to the new point and do not establish the cause of an incident or independently verify a fix.

When the tracked finding set changes, the comparison records the set change. It cannot isolate status, severity, age, observation or confirmation changes for the subset of findings present in both captures. Policy, endpoint context and correlation are compared independently.

Each capture retains the effective scoring policy and its version as recorded at evaluation time. Its SHA-256 fingerprint covers canonical weights and mappings, version and scoring algorithm revision. Changes to a weight under the same label receive a different fingerprint. Policy changes do not recompute stored scores. History accepts up to 1,024 entries each in the rule confidence and correlation mappings, with a 2 MiB limit on the canonical policy. A policy outside these bounds leaves the bucket uncaptured.

## Retention and reports

Core exposes up to 90 rolling days and stores up to 250,000 endpoint measurements. Reads exclude expired points immediately. Successful captures prune expired rows and policy records unused by retained captures. Reaching the row limit drops the oldest complete captures, so a larger fleet can have a shorter history. Comparison inputs are stored only for the latest complete capture. The older measured timestamps and factor codes remain available until the corresponding points expire.

Security reports generated through the loopback listener show organization measurements retained inside the selected UTC period, alongside a separate current evaluation. Report generation and the Desktop read existing points. Older backups can initialize empty history tables. New backups include retained history in the consistent database snapshot. A restore returns the history in that archive and sampling continues in subsequent eligible buckets.

## Local administrator API

`GET /api/admin/risk-history?hours=168` returns organization history. `GET /api/admin/risk-history/{endpointId}?hours=168` returns one endpoint's history. Supported values are 24, 168, 720 and 2160, with 168 as the default. Results have at most 361 points. The API requires a local administrator session and returns `Cache-Control: no-store`. The Agent-only listener denies the route.
