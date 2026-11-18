---
status: proposed
---

# News Items are read once for every Customer, matched to each by rules, and attacks on Peers reach people as context

A Security Team wants to hear about the attacks around it, not only about the Vulnerabilities of its open Findings: a ransomware group hitting manufacturers this week, a campaign against a firewall it runs, a breach at one of its suppliers, a leak site that names it. Most of that news names no CVE, so it never becomes a Finding (ADR 0009) nor an Advisory (ADR 0022), and most of it is about other organizations. barbattack reads it anyway and hands it to people, saying how close it comes to the Customer: **an attack on an organization of the Customer's sector is context, never a sign that the Customer is exposed.**

## What a News Item holds

A **News Item** is one article or leak-site post that a Feed publishes; a notice about Vulnerabilities from a vendor or a CERT is an Advisory (ADR 0022). It belongs to no Customer, and its text is as untrusted as any Feed's. It may say things about Vulnerabilities (that one is exploited, has a public proof of concept or a fix), and it may report **Reported Attacks**: the victim, its sectors and countries, the kind of attack, the attacker it names, and the Vulnerabilities and Products used. A Reported Attack is what the source claims, which barbattack never confirms. A leak-site post is the attacker's own claim, and is always shown as one.

## Read once, matched by rules, explained per Customer

1. **Each News Item is stored on receipt** as a STIX `report` (ADR 0010), with no model, by a `HandleNews` handler on `ingest.Feed.Handle`, as Advisories are (ADR 0022). Unlike a Vulnerability or an Advisory, it is kept whether or not it names anything stored (ADR 0015): what makes it relevant, a victim's sector or a Customer's brand, is known only once it is read, and no model is called inside a Feed's transaction. A structured Feed, such as a leak-site tracker, already says who the victim is, with its sector, country and domain, and its adapter writes them. A text Feed, such as a news site's RSS, gives only text, and its adapter only finds the CVE IDs in it. `internal/news` reads a Reported Attack the same way from either.
2. **The Reader reads each text News Item once**, for every Customer at once, and states its Reported Attacks and what it says about Vulnerabilities, each with a quote. It reads no Customer's data, so a News Item costs one request however many Customers it reaches, and the Reader cannot carry one Customer's context into another's.
3. **Rules give each News Item its Relevance to each Customer**, never a model, so the same News Item and Customer always get the same answer. From closest to farthest:

   | Relevance | When | Where it goes |
   |---|---|---|
   | **Named** | a victim's domain is one of the Customer's domains, or its name is one of its brands | first in the News Digest, and a notice to the Security Team channel through the Slack delivery queue once it exists (#96, #105) |
   | **Finding** | it names the Vulnerability of one of the Customer's open Findings | the Finding's Dossier, so the Prioritizer and Luna can cite it, and the News Digest |
   | **Footprint** | it names a Product the Customer's Active Assets run, or a technology or third party its Business Context states | the News Digest |
   | **Peer** | it reports an attack on a Peer: a victim that shares a sector with the Customer's Business Context | the News Digest, marked as context |

   A News Item takes the closest Relevance that applies and keeps every reason. Closed Findings and Inactive Assets match nothing, and a News Item with no Relevance does not reach the Customer. A Business Context with no sector stated has no Peers, and its digest says so. In the rules' order, a Peer that also shares a country with the Customer comes first, then the newest. A digest holds at most 50 News Items; above that, the rules keep the closest Relevance first, in that order.
4. **The Editor writes each Customer's News Digest**, once a day when anything new is relevant. One request reads the Customer's Business Context Brief (ADR 0017) and the relevant News Items with what the Reader stated, orders the News Items within each Relevance and says why each may matter, weighing the Customer's Critical Services, data, regulations, Concerns and countries. The groups and their order come from the rules: the Editor cannot add a News Item, leave one out or move one to another Relevance. Code, not the model, writes the labels a reader must not miss: each Peer item says "Ataque a una organización de su sector: es contexto, no indica que ustedes estén expuestos", and each leak-site claim "Reclamado por <atacante> en su sitio de filtración".

Text is compared case-insensitively after trimming. A Product of an Asset is CPE vendor and product tokens (ADR 0019), which an article never writes, so the Reader states each Product it names both as quoted and as the CPE tokens it takes it to be, and Footprint compares the tokens. A Business Context's technologies, third parties and brands are free text (ADR 0017), compared with what the Reader quotes. A wrong token or a missed name loses context, never a Finding.

**Peers come only from News Items, never from another Customer.** "A Customer of your sector has this Finding" would tell one Customer about another.

## How the Reader and the Editor are kept honest

Both follow ADR 0016: one structured-output call each, no tools, what they read in the user message as data, a verifier without a model, one retry told what was wrong, and a Run that records the model and the hash of the prompt. They run on `claude-haiku-5-5`, overridable with `READER_MODEL` and `EDITOR_MODEL`.

- **The Reader**: every quote must appear in the News Item's title or text once whitespace is collapsed; every CVE ID, victim, attacker and Product it states must appear in one of its quotes; sectors must be codes of `business.Sectors()`, countries ISO 3166-1 alpha-2 and kinds of attack codes of `business.Concerns()`, the vocabularies a Customer states its Business Context in (ADR 0017); and it writes no URL. **It cannot judge a sector, a country or a CPE token inferred from a quote**, such as "a Monterrey auto-parts maker" read as `automotive` and `MX`, or "FortiOS" as `fortinet`/`fortios`, so a Peer or a Footprint is only as good as that inference, which is one more reason both are only context. It runs as a job in `serve`, never inside a Feed's transaction, on the articles of the last 7 days and at most 300 a day (`agents.MaxReadingsPerDay`), as the Cartógrafo does (ADR 0024): a News Item it fails on twice or refuses keeps only what its adapter found and is tried again in a later run, at most 3 times, and a model that cannot be called spends no attempt. What it states is stored as an Agent's output beside the News Item, not as STIX (ADR 0010).
- **The Editor**: it is given each News Item under a key and must answer every key exactly once; code then orders its answer within each Relevance, so it can neither add, drop nor move a News Item. Each reason is at most 320 characters, cites by JSON pointer each value of the Business Context it relies on, which must be there, names no CVE ID its News Item does not, has no URL and none of a list of filler phrases ("es importante", "mantenerse alerta", "buenas prácticas"…) that say nothing about the Customer. A digest without a verified Editor is still stored and shown, in the rules' order and without reasons, because the rules, not the Editor, decide what a Customer sees.

## When it runs, what it stores and where it is served

A job in `serve` runs every hour, 20 minutes after `serve` starts so the Feeds' first pulls are stored: the Reader reads, and then each active Customer whose last News Digest ended a day ago or more gets the next one, with the News Items that became ready since, reaching back at most 7 days. A Customer nothing new is relevant to gets none. `barbackend agent news` runs it once.

| Table | Holds |
|---|---|
| `news_items` | One row per News Item: its STIX `report` as `jsonb`, its Feed, kind, publication date and CVE IDs, and `ready_at`, when it can go in a digest: on receipt for a leak post, once its reading is final for an article |
| `news_victims`, `news_item_victims` | The victims structured Feeds name, one row per STIX `identity`, and which News Items refer to each |
| `news_readings` | The Reader's reading of each article, `read` or `failed`, with its attempts, model and prompt id |
| `news_digests` | Each Customer's digests: the period, the Business Context version read, the count per Relevance, and the digest as `jsonb` |

`GET /news-digests` lists a Customer's digests and `GET /news-digests/{id}` reads one, grouped by Relevance, for every User of the Customer; a Platform Admin reads none. When the rules compare a leak post with a Customer's Concerns, it counts as ransomware and extortion, which is what a leak site is for.

News Items are the most hostile text barbattack reads: anyone who can publish a post or a leak-site entry can put words in a Feed. Neither Agent has a tool to reach, and everything they write is for a person to read, rendered as plain text (ADR 0016).

## The first Feeds

Each is a Feed like any other, with its own interval (ADR 0011), short enough that its window never fills between two Pulls:

| Feed | Format | What it adds | Interval |
|---|---|---|---|
| ransomware.live, only with `RANSOMWARELIVE_ENABLED=true` | JSON | leak-site victims with their sector, country and domain, without a model | 1h |
| The Record, The Hacker News, SecurityWeek, Dark Reading, DataBreaches.net | RSS, a summary per article | Reported Attacks, through the Reader | 1h |
| WeLiveSecurity (ESET, Spanish), Una al día (Hispasec) | RSS | the same, in Spanish and about Latin America | 2h |

A news site's RSS gives a few hundred characters of each article, and the Reader reads only that: fetching each article's page is left out, for the sites' terms and the cost. `internal/feeds/rss` is one adapter configured per text Feed, so adding one is a name, a URL and an interval. CISA, INCIBE-CERT, Cisco PSIRT and ZDI publish Advisories, not News Items: they may become Advisory Feeds beside AWS under ADR 0022, and are not part of this ADR. ransomware.live's own sector names are mapped to `business.Sectors()` in its adapter; one it cannot map is left out, never guessed.

## Where the code goes

This adds layers to ADR 0008:

```
internal/
  feeds/
    rss/            every text Feed                   -> feeds, httpx, stixext
    ransomwarelive/ leak-site victims                 -> feeds, httpx, stixext
  newsitems/        use case storing what news Feeds emit -> news, postgres, stixext
  agents/           gains the Reader and the Editor   -> news too
  news/             pure domain: News Item, Reported Attack, Relevance, the Reader's verifier -> business, inventory, stixext
```

`postgres` and `assessment` may import `news`: the Dossier gains the newest News Items that name its Vulnerability, beside its Advisories (ADR 0022).

## Consequences

- **News Items are the one Feed object stored on receipt**, with each one's Feed, published date and CVE IDs extracted, where ADR 0015 keeps a Vulnerability only when it opens a Finding and ADR 0022 an Advisory only when it names one. An RSS window holds 10 to 50 items and cannot be asked again later. How long one that no Customer found relevant is kept is not decided.
- **A News Item that names no CVE is kept**, where an Advisory without one is skipped (ADR 0010, ADR 0022).
- **Finding relevance reads the open Findings ADR 0020 stores.** Dossiers are built from them (ADR 0026), so News Items join a Dossier beside its Advisories (`docs/agents-pending.md`, item 5).
- **Nothing here changes a Score or an order** (ADR 0009). If "exploited, says CISA" should raise a Score, that is a new Scoring Model fed by a structured signal, never by what the Reader states.
- **It costs one Reader request per text News Item**, tens to a few hundred a day for all Customers together, capped at 300 a day, and one Editor request per Customer and day with news. There is no quota per Customer yet (`docs/agents-pending.md`, item 4).
- **Ransomware.live is off unless an operator turns it on.** Its terms (www.ransomware.live/t&c) forbid using its data in a commercial product without its owner's written approval, and require "Source: Ransomware.live", linked, wherever its data is shown, which the dashboard does. Its free API is for personal use, one request a minute per endpoint; its PRO API (`api-pro.ransomware.live`, with an API key) is what an approved deployment should poll, which the adapter does not support yet. Until then Peers come only from the articles the Reader reads.
- **BleepingComputer is left out**: its feed answers automated clients with a Cloudflare challenge, and getting past it would mean dodging its bot protection.

## Considered Options

- **A model inside the Feed adapter**: rejected; ingestion would stop being repeatable and would fail whenever Anthropic does, and adapters import no Agent (ADR 0008).
- **The Prioritizer reading raw News Items in each Dossier**: rejected; it would pay per Finding of every Customer instead of once per News Item, and fill the Dossier with long hostile text (ADR 0016, Actividad 6).
- **Keep only News Items that name a stored Vulnerability, as Advisories are (ADR 0022)**: rejected; an attack on a Peer names none, and that is most of this news.
- **A model deciding Relevance per Customer**: rejected; the same News Item could reach a Customer one day and not the next, and each decision would be a request per Customer.
- **Only CIRCL Vulnerability-Lookup's sightings**: rejected as the only source; they are counted per CVE, so they say nothing of attacks on Peers. They may still become a Feed for the Dossier.
- **Peers by country alone**: deferred; every attack in a Customer's countries, whatever the sector, would fill the digest. A shared country orders Peers instead.
- **Resolving attackers to ATT&CK groups**: deferred; the name as the source writes it is kept until matching by name and alias is worth its false matches.
