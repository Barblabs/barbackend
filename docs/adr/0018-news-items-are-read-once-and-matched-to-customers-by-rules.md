---
status: proposed
---

# News Items are read once for every Customer, matched to each by rules, and attacks on Peers reach people as context

A Security Team wants to hear about the attacks around it, not only about the Vulnerabilities of its open Findings: a ransomware group hitting manufacturers this week, a campaign against a firewall it runs, a breach at one of its suppliers, a leak site that names it. Most of that news names no CVE, so it never becomes a Finding (ADR 0009), and most of it is about other organizations. barbattack reads it anyway and hands it to people, saying how close it comes to the Customer: **an attack on an organization of the Customer's sector is context, never a sign that the Customer is exposed.**

## What a News Item holds

A **News Item** is one article, advisory or leak-site post that a Feed publishes. It belongs to no Customer, and its text is as untrusted as any Feed's. It may say things about Vulnerabilities (that one is exploited, has a public proof of concept or a fix), and it may report **Reported Attacks**: the victim, its sectors and countries, the kind of attack, the attacker it names, and the Vulnerabilities and Products used. A Reported Attack is what the source claims, which barbattack never confirms. A leak-site post is the attacker's own claim, and is always shown as one.

## Read once, matched by rules, explained per Customer

1. **A Feed adapter stores each News Item** as a STIX `report` (ADR 0010), with no model. A structured Feed, such as a leak-site tracker, already says who the victim is, with its sector, country and domain, and its adapter writes them. A text Feed, such as a news site's RSS, gives only text, and its adapter only finds the CVE IDs in it. `internal/news` reads a Reported Attack the same way from either.
2. **The Reader reads each text News Item once**, for every Customer at once, and states its Reported Attacks and what it says about Vulnerabilities, each with a quote. It reads no Customer's data, so a News Item costs one request however many Customers it reaches, and the Reader cannot carry one Customer's context into another's.
3. **Rules give each News Item its Relevance to each Customer**, never a model, so the same News Item and Customer always get the same answer. From closest to farthest:

   | Relevance | When | Where it goes |
   |---|---|---|
   | **Named** | a victim's domain is one of the Customer's domains, or its name is one of its brands | first in the News Digest, and a notice to the Security Team channel through the Slack delivery queue once it exists (#96, #105) |
   | **Finding** | it names the Vulnerability of one of the Customer's open Findings | the Finding's Dossier, so the Prioritizer and Luna can cite it, and the News Digest |
   | **Footprint** | it names a Product the Customer's Active Assets run, or a technology or third party its Business Context states | the News Digest |
   | **Peer** | it reports an attack on a Peer: a victim that shares a sector with the Customer's Business Context | the News Digest, marked as context |

   A News Item takes the closest Relevance that applies and keeps every reason. Remediated Findings and Inactive Assets match nothing, and a News Item with no Relevance does not reach the Customer. A Business Context with no sector stated has no Peers, and its digest says so. In the rules' order, a Peer that also shares a country with the Customer comes first, then the newest. A digest holds at most 50 News Items; above that, the rules keep the closest Relevance first, in that order.
4. **The Editor writes each Customer's News Digest**, once a day when anything new is relevant. One request reads the Customer's Business Context Brief (ADR 0017) and the relevant News Items with what the Reader stated, orders the News Items within each Relevance and says why each may matter, weighing the Customer's Critical Services, data, regulations, Concerns and countries. The groups and their order come from the rules: the Editor cannot add a News Item, leave one out or move one to another Relevance. Code, not the model, writes the labels a reader must not miss: each Peer item says "Ataque a una organización de su sector: es contexto, no indica que ustedes estén expuestos", and each leak-site claim "Reclamado por <atacante> en su sitio de filtración".

Text is compared case-insensitively after trimming. A Business Context's technologies, third parties and brands are free text (ADR 0017), and so are Products until ADR 0010's open question on how a Product is keyed is settled, so Footprint misses more than it finds until then. A miss loses context, never a Finding.

**Peers come only from News Items, never from another Customer.** "A Customer of your sector has this Finding" would tell one Customer about another.

## How the Reader and the Editor are kept honest

Both follow ADR 0016: one structured-output call each, no tools, what they read in the user message as data, a verifier without a model, one retry told what was wrong, and a Run that records the model and the hash of the prompt. They run on `claude-haiku-5-5`, overridable with `READER_MODEL` and `EDITOR_MODEL`.

- **The Reader**: every quote must appear in the News Item's title or text once whitespace is collapsed; every CVE ID, victim, attacker and Product it states must appear in one of its quotes; sectors must be codes of `business.Sectors()`, countries ISO 3166-1 alpha-2 and kinds of attack codes of `business.Concerns()`, the vocabularies a Customer states its Business Context in (ADR 0017); and it writes no URL. **It cannot judge a sector or a country inferred from a quote**, such as "a Monterrey auto-parts maker" read as `automotive` and `MX`, so a Peer is only as good as that inference, which is one more reason a Peer is only context. A News Item the Reader fails on twice or refuses keeps only what its adapter found, and is not read again. What it states is stored as an Agent's output beside the News Item, not as STIX (ADR 0010).
- **The Editor**: every relevant News Item appears exactly once, under its Relevance; a reason cites by JSON pointer only the News Item, what the Reader stated of it and the Business Context; and it names no CVE, version or URL those do not. A digest without a verified Editor is still stored and shown, in the rules' order and without reasons, because the rules, not the Editor, decide what a Customer sees.

News Items are the most hostile text barbattack reads: anyone who can publish a post or a leak-site entry can put words in a Feed. Neither Agent has a tool to reach, and everything they write is for a person to read, rendered as plain text (ADR 0016).

## The first Feeds

Each is a Feed like any other, with its own interval (ADR 0011), short enough that its window never fills between two Pulls:

| Feed | Format | What it adds | Interval |
|---|---|---|---|
| ransomware.live | JSON | leak-site victims with their sector, country and domain, without a model | 1h |
| The Record, BleepingComputer, The Hacker News, SecurityWeek, Dark Reading, DataBreaches.net | RSS, a summary per article | Reported Attacks, through the Reader | 1h |
| WeLiveSecurity (ESET, Spanish), Una al día (Hispasec) | RSS | the same, in Spanish and about Latin America | 2h |
| CISA, INCIBE-CERT, Cisco PSIRT, ZDI, AWS | RSS, whole advisories | what they say about Vulnerabilities, almost always by CVE | 2h |

A news site's RSS gives a few hundred characters of each article, and the Reader reads only that: fetching each article's page is left out, for the sites' terms and the cost. `internal/feeds/rss` is one adapter configured per text Feed, so adding one is a name, a URL and an interval, and `aws` becomes one of them. ransomware.live's own sector names are mapped to `business.Sectors()` in its adapter; one it cannot map is left out, never guessed.

## Where the code goes

This adds layers to ADR 0008:

```
internal/
  feeds/
    rss/            every text Feed                   -> feeds, httpx, stixext
    ransomwarelive/ leak-site victims                 -> feeds, httpx, stixext
  ingest/           also stores what news Feeds emit  -> feeds, news, postgres, stixext
  agents/           gains the Reader and the Editor   -> news too
  news/             pure domain: News Item, Reported Attack, Relevance, the Reader's verifier -> business, inventory, stixext
```

`postgres` and `assessment` may import `news`: the Dossier gains the newest News Items that name its Vulnerability.

## Consequences

- **Feeds start being stored, with News Items**, in the shape ADR 0010 intends, with each one's Feed, published date and CVE IDs extracted. ADR 0016 did not store Feeds before reading NVD; for News Items there is no other way, since an RSS window holds 10 to 50 items and cannot be asked about a CVE.
- **A News Item that names no CVE is kept**, where ADR 0010 skipped it.
- **Finding relevance waits for stored Findings** (`docs/agents-pending.md`, item 2). Until then, the stand-in `agent finding` can attach News Items by CVE like any other Feed record.
- **Nothing here changes a Score or an order** (ADR 0009). If "exploited, says CISA" should raise a Score, that is a new Scoring Model fed by a structured signal, never by what the Reader states.
- **It costs one Reader request per text News Item**, tens to a few hundred a day for all Customers together, and one Editor request per Customer and day with news. There is no quota yet (`docs/agents-pending.md`, item 4).
- ransomware.live's terms of use and rate limits must be checked before it is polled in production.

## Considered Options

- **A model inside the Feed adapter**: rejected; ingestion would stop being repeatable and would fail whenever Anthropic does, and adapters import no Agent (ADR 0008).
- **The Prioritizer reading raw News Items in each Dossier**: rejected; it would pay per Finding of every Customer instead of once per News Item, and fill the Dossier with long hostile text (ADR 0016, Actividad 6).
- **A model deciding Relevance per Customer**: rejected; the same News Item could reach a Customer one day and not the next, and each decision would be a request per Customer.
- **Only CIRCL Vulnerability-Lookup's sightings**: rejected as the only source; they are counted per CVE, so they say nothing of attacks on Peers. They may still become a Feed for the Dossier.
- **Peers by country alone**: deferred; every attack in a Customer's countries, whatever the sector, would fill the digest. A shared country orders Peers instead.
- **Resolving attackers to ATT&CK groups**: deferred; the name as the source writes it is kept until matching by name and alias is worth its false matches.
