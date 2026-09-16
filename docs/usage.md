# Scan usage and cost

Scrutineer records model usage on each scan and aggregates completed and failed skill runs on the `/usage` page. The **By skill** view is the instance's observed cost range: min, median, p90, max, total, token totals and turn-count percentiles are calculated from the scans stored in that instance. These corpus measurements are more useful than a fixed price estimate because model, effort, repository content and provider pricing all affect cost.

## Cost drivers

The **Cost drivers** view compares scan cost with three inexpensive workload proxies:

- **SLOC** is `lines.total_lines` from the latest successful `repo-overview` report for the repository.
- **Dependency manifests** is the current number of distinct non-empty `Dependency.ManifestPath` values stored for the repository.
- **Phase 1 sinks** is the number of entries in the latest positive-cost completed `security-deep-dive` report for the repository.

Repository-wide SLOC and manifest measurements are not attached to subpath or focus-area scans because the full-repository value would overstate their scope. They are deliberately coarse, inexpensive current-corpus proxies rather than historical commit snapshots: SLOC can lag until `repo-overview` runs again, and dependency rows reflect the latest successful inventory. Phase 1 sink counts are attached only to the selected deep-dive scan, which avoids loading and parsing the repository's complete deep-dive history on every page view.

Correlations are calculated independently per skill over positive-cost runs. A row appears once at least three matched observations exist and both cost and the driver vary. The reported value is Pearson's correlation coefficient (`r`): values near `1` indicate that cost tends to rise with the proxy, values near `-1` indicate an inverse relationship and values near `0` indicate little linear relationship. Correlation describes the stored corpus and does not prove that a proxy caused the cost.

## Outliers

The outlier table lists every positive-cost scan whose cost is at least ten times the positive-cost median for that skill. Each row links to the scan and repository and includes model, runner profile, turns and any matched driver measurements. Inspect the linked scan's transcript, report and runtime settings before assigning a cause; common explanations include a larger-than-usual analysis surface, a large sink inventory, repeated tool work, retries or a different model configuration.

Zero-cost rows are retained in the normal usage totals but excluded from correlation and outlier baselines. This prevents historical rows without captured billing data and genuinely free runs from forcing the outlier median to zero.
