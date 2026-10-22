# Feeds are pulled by in-process polling on per-feed fixed windows

barbattack consumes threat intelligence Feeds by fetching them itself: each Feed adapter under `internal/feeds` fetches, parses and normalizes its own records, and the `serve` process polls every Feed on its own interval — the first pull immediately at startup, then on a ticker, with an in-flight guard so a slow pull skips its next tick. The same use case serves the manual `barbackend feed pull` command. NVD supports a modification window; we query the last 24 hours rather than remembering the last successful Pull, because nothing stores run state yet, and a gap older than the window is accepted loss. Every other Feed is inherently a full pull (EPSS's daily file, the KEV catalog, the ATT&CK bundle, AWS's rolling RSS window). ADR 0007's full-snapshot rule is scoped to CMDB reconciliation, where an Asset missing from a snapshot is deactivated; it does not apply to Feeds, whose records are added and updated, never removed by absence.

## Poll intervals

Each Feed is polled on a fixed window, a constant next to its adapter:

| Feed | Interval | Why |
|---|---|---|
| KEV | 1h | CISA publishes additions outside any schedule; the catalog is small |
| NVD | 2h | Paced by the public rate limit; the 24h query window leaves slack for gaps |
| EPSS | 24h | FIRST publishes one score file per day |
| ATT&CK | 12h | The bundle changes on MITRE's release cadence, which is slow |
| AWS | 6h | The RSS window is rolling; 6h keeps up with bulletin bursts |

The interval belongs to the Feed, so a new adapter lands with its own constant and the serve process learns no new behaviour. A window shorter than the source's publish cadence only costs requests; a window longer than the query window (NVD's 24h) risks losing data, which is why NVD's is 2h and not 24h+.

## Considered Options

- **External scheduler (CI cron)**: rejected; couples freshness to another system and its delays, while the one long-running process already exists.
- **Webhook receivers**: rejected; none of the Feeds offer push, and a webhook cannot be registered on a repository we do not own.
- **Remembering the last successful Pull per Feed**: rejected for now; it needs storage, which the ingestion step deliberately excludes.
