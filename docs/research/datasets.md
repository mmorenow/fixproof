# Open-source projects and datasets for evaluating duplicate confirmation of vulnerability reports

Research date: 2026-10-06. Numbers marked "measured" come from data I downloaded or queried today.

**Bottom line:** No public project or dataset checks whether two human-written reports share a root cause or a fix. Every tool found ranks candidates by text similarity, identifiers or keyword weights, and the two code-grounded ones are either pre-alpha or matching against a codebase rather than between reports. The best ground truth with real human report text, explicit duplicate labels and a known fix is the Chromium/Firefox security-bug data. The largest pool of real triage threads is GitLab's public HackerOne issues, which are plentiful but have few duplicate labels.

---

## 1. Open-source projects

| Project | Link | Stars / activity | What it does | What it does NOT do |
|---|---|---|---|---|
| Sentriage | https://github.com/russellb/sentriage | 2★, Apache-2.0, last push 2026-06-30 | AI triage of GitHub private vulnerability reports (GHSA drafts). It syncs them to a tracking repo, checks for duplicates against existing reports, validates against source code and recommends a disposition with a confidence score. A human always makes the final decision (README). | No published dedup method or evaluation, and no ground-truth dataset. The duplicate check is an LLM "skill"; I did not find root-cause or fix-equivalence logic. |
| Kritolith | https://github.com/ergasterion-dev/kritolith | 1★, Apache-2.0, created 2026-09-23, **pre-alpha ("commands … don't work yet")** | Planned pipeline: pull files, functions and commits out of a report, check those claims against git, dedupe against past reports and an OSV mirror, reproduce the PoC in a gVisor sandbox, then emit a signed verdict (README). | Not working yet. Its grounding depends on the report naming code, which bug bounty reports usually do not. No evaluation. **Closest in spirit to post-retrieval confirmation.** |
| bounty-triage | https://github.com/sonofnos/bounty-triage | 0★, created 2026-09-29 | Predicts vulnerability class, severity and duplicates for RustSec. Its duplicate pairs are 384 NVD descriptions written independently of the matching RustSec advisories. TF-IDF char n-grams put the right advisory first 0.883 of the time; MiniLM scores 0.737 (README). | Retrieval only, on advisory text rather than reporter text. Its evaluation design (independently written texts for the same bug) is reusable. |
| Dup-Scout | https://github.com/JRBusiness/Dup-Scout | 4★, MIT, Jul 2026 | Reporter-side prior-art check: searches a repo's PRs, issues, commits, releases and web3 audits for a finding before it is submitted, and detects silent fixes against a scope tag (README). | Keyword and score matching only; it does not compare one report against another. |
| osv-dedupe | https://github.com/rahulreddykarne/osv-dedupe | 0★, MIT, 2026-10-05 | Scores a finding against OSV/NVD advisories for a PyPI package with hand-set weights (OSV hit +0.45, CWE match +0.25, file/function hint +0.10…) (README). | Heuristic, matches against advisories only, no evaluation. |
| cve-dedup-checker | https://github.com/jashidsany/cve-dedup-checker | 0★, MIT, Apr 2026 | Queries NVD, OSV and GHSA in parallel to see whether a finding is already known (repo description). | Lookup only. |
| DefectDojo | https://github.com/DefectDojo/django-DefectDojo | 4,984★, BSD-3, active | Deduplicates scanner findings with four algorithms: `legacy`, `unique_id_from_tool`, `hash_code`, and `unique_id_from_tool_or_hash_code`, plus optional endpoint host/path matching (`dojo/settings/settings.dist.py`). | Deterministic hashes of scanner fields. No natural-language reports and no semantic or root-cause logic. |
| osv.dev alias / related / upstream computation | https://github.com/google/osv.dev (`go/cmd/relations/alias.go`, `related.go`, `upstream.go`) | 2,961★, Apache-2.0, active | Alias groups are the transitive closure over declared `aliases` IDs (comments in `alias.go`). The OSV schema calls two records aliases when "a single patch addresses both", symmetric and transitive; `related` covers similar but different bugs (https://ossf.github.io/osv-schema/). | It only combines the links that feeds already declared; it never infers a duplicate. The schema's alias definition does match "same root cause, same fix". |
| VulnerableCode / vcs-collector | https://github.com/aboutcode-org/vulnerablecode (708★), https://github.com/aboutcode-data/vulnerablecode-vcs-collector | active | Aggregates and correlates advisories across sources; the collector gathers CVE-related fix commits, PRs and issues. | Correlates records, not incoming reports. |
| CVE → fix-commit mappers | PatchHolmes https://github.com/Aizhouym/PatchHolmes (2★, AACL-IJCNLP 2026, hybrid retrieval plus agent loop); SAP Project KB `prospector` https://github.com/SAP/project-kb (134★); MoreFixes miner https://github.com/JafarAkhondali/Morefixes (85★) | — | Map an advisory to its fix commit(s). | Useful as a component (report → candidate fix → compare fixes), but none of them dedupe. |
| HackerOne report archives | reddelexc/hackerone-reports https://github.com/reddelexc/hackerone-reports (6,593★); ajaysenr/HackerOne-Disclosed-Reports https://github.com/ajaysenr/HackerOne-Disclosed-Reports (60★, updated 2026-10-06, 12,556 reports in `index.json` with `substate`); aldaor/HackerOneReports (360★, stale since 2022) | — | Lists and metadata of disclosed reports. | No duplicate→original links (ajaysenr does carry `substate`). |
| huntr-hacktivity | https://github.com/dwisiswant0/huntr-hacktivity | 17★, stale since 2023 | Watcher for huntr disclosures. | Stale. Apache has stopped accepting huntr.com reports, citing volume, low quality and AI-generated submissions (https://security.apache.org/huntr/). |
| "AI slop" tooling | bug-reaper https://github.com/shaniidev/bug-reaper (73★) | — | Reporter-side agent skill that aims at evidence-based reports. | I found no maintainer-side open-source slop detector besides Kritolith and Sentriage. |

I found no open replication repo or dataset for **duplicate bug report detection applied to security reports**. The general duplicate-bug-report literature has replication packages, e.g. https://github.com/soarsmu/TOSEM-DBRD and https://github.com/SigmaJahan/Textual-Dissimilarity-Analysis-for-Duplicate-Bug-Report-Detection.

---

## 2. Datasets

| Name | Link | Size | Labels available | Fix commit? | Duplicate labels? | Human-written external-behavior text? | License / access |
|---|---|---|---|---|---|---|---|
| SCP 2025 duplicate vulnerability records (Zhu, Yang, Pan, Zhou) | DOI 10.1016/j.scico.2025.103357 (SCP vol. 247, Jan 2026); SSRN preprint 10.2139/ssrn.5102551 (Crossref) | **UNVERIFIED.** ScienceDirect and SSRN returned 403; searches of GitHub, Zenodo and the web found no artifact link. | Duplicate record pairs across CVE/OSV/GHSA (per task brief) | ? | Yes (record-level) | No (advisory text) | **UNVERIFIED.** Email the authors. |
| **Atefi et al., Chromium & Firefox VRP data** | https://doi.org/10.6084/m9.figshare.22056617 (paper: "The Benefits of Vulnerability Discovery and Bug Bounty Programs: Case Studies of Chromium and Firefox", WWW 2023, arXiv 2301.12092) | Chromium: 25,358 security reports, **3,905 duplicates (1,900 external)**, 2008–2022. Firefox: 6,066 reports, **1,262 duplicates (364 external)**, 2004–2022 (measured from CSVs). | `ReportID` → `PseudoID` (original, resolved by following MergedInto chains), severity, component, weakness type, IsExternal, IsExploited, fixed timestamp | Not in the CSV. Fixed timestamps are included; commits come from the tracker or commit footers. | **Yes, explicit** | Summary/title only in the CSV. The full reporter text is on the public tracker. | **CC BY 4.0.** CSVs are 2 MB; the 73 MB code zip has the scrapers. |
| Mozilla Bugzilla (live) | REST: `https://bugzilla.mozilla.org/rest/bug?resolution=DUPLICATE&keywords=sec-high…` | Measured: **1,335 public DUPLICATE bugs** with sec-critical/high/moderate/low keywords (152 / 652 / 325 / 206), years 2000–2026 (277 created in 2026). 1,096 distinct `dupe_of` targets: 1,088 public, **947 FIXED**. | `dupe_of`, keywords (sec-*, csectype-uaf…), product/component | Yes, for fixed originals via linked commits. Mozilla commit messages cite "Bug N" (convention, not checked here). | **Yes, `dupe_of` field** | Mixed: external reporters, internal staff and fuzzers (crash signatures) | Public API, no key needed for public bugs. Undisclosed security bugs stay hidden. |
| Chromium issue tracker (live) | https://issues.chromium.org (Buganizer) | 3,905+ duplicates through 2022 (Atefi); current total UNVERIFIED | Status Duplicate plus a merged-into link; severity; VRP labels | Yes (Gerrit commits; "Bug:/Fixed:" footers are the Chromium convention, not checked here) | **Yes** | Yes for external VRP reports | Undocumented JSON endpoint `issues.chromium.org/action/issues/<id>` works per issue (tested). The list/search endpoint returned 405. Expect scraping, not a stable API. |
| **HackerOne official HF dataset** | https://huggingface.co/datasets/Hacker0x01/hackerone_disclosed_reports | 12,618 reports, snapshot to 2024-05-15. Measured: **271 duplicates, 237 with `original_report_id`, 113 pairs where the original is also in the dataset** (originals: 54 resolved, 40 informative, 12 N/A, 7 duplicate). | substate, `original_report_id`, weakness, scope asset, full `vulnerability_information` | Rare (no field). Only OSS programs can be linked to commits. | **Yes (field)** | **Yes**: reporter-written steps, payloads and URLs. Median duplicate text is 957 chars. | No license tag on the card (tags only `region:us`). HackerOne ToS applies. UNVERIFIED for redistribution. |
| HackerOne live disclosed JSON | `https://hackerone.com/reports/<id>.json` (tested) | Measured across the 289 disclosed duplicates in the ajaysenr index: **249 have `original_report_id`, 116 originals are also disclosed**, 238 have >200 chars of text. Top programs with pairs: sifchain 22, nextcloud 8, paragonie 7, gratipay 7, legalrobot 5, kubernetes 4, curl 3. | `substate`, `original_report_id`, `original_report_url`, `cve_ids`, weakness, scope | Only 10 linked originals carry CVE IDs. | **Yes** | **Yes** | Unauthenticated JSON; be polite with rate limits. HackerOne ToS. |
| **GitLab gitlab-org/gitlab public HackerOne issues** | GraphQL `project(fullPath:"gitlab-org/gitlab"){issues(labelName:["HackerOne"]){… closedAsDuplicateOf}}` | Measured: 1,223 issues labeled HackerOne (REST x-total), **1,212 closed**. Only **19 closed-as-duplicate**, 13 of whose targets are also HackerOne issues. Only 30 show linked MRs. | The issue body embeds "HackerOne report #N by <user>", a **"HackerOne Analyst Summary"**, steps to reproduce and screenshots. Labels include severity and `HackerOneDuo::commented`. | Indirect: fixes land in the private security mirror. CVE and reporter credit appear in patch-release posts, e.g. https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-3-2-released/ and https://about.gitlab.com/releases/2026/01/21/patch-release-gitlab-18-8-2-released/ | Few explicit | **Yes, and closest to the GitLab PSIRT workflow** | Public API, no auth. My inference, not verified: duplicates closed on HackerOne itself probably never become GitLab issues. |
| GHSA "Duplicate Advisory" (withdrawn) | https://github.com/github/advisory-database ; OSV per-ecosystem zips | Measured over 7 OSV ecosystems (npm 335, PyPI 190, Packagist 107, Go 99, crates.io 86, Maven 78, RubyGems 53): **948 withdrawn advisories whose text says "duplicate of GHSA-…"**. The original description is kept. | Explicit duplicate-of GHSA ID; aliases; CWE | Yes, via the canonical advisory's references | **Yes (in text)** | No (advisory or CVE prose, often near-identical) | CC-BY-4.0 |
| OSV.dev (all ecosystems) | https://osv.dev ; `osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip` (all.zip is 2.6 GB) | Measured: PyPI 26,089 records (14,216 aliases, 72 related, 8,075 with a commit URL, 1,023 huntr refs). Go 9,492 (9,304 aliases, 1,118 related). Maven 7,168. Packagist 7,257 (593 huntr refs). RubyGems 5,438 (69 HackerOne refs). crates.io 2,892. npm 230,021 (mostly MAL- malicious-package entries; 273 HackerOne refs). OSS-Fuzz 4,255 (all with REPORT links and GIT ranges). `upstream` was 0 in all of these ecosystems. | aliases (same fix per schema), related, withdrawn, references by type | Yes (FIX refs and GIT ranges) | Alias groups, record-level | Mostly no. Huntr and HackerOne REPORT links point to reporter text. | Apache-2.0 schema; per-source data licenses |
| CVE rejected as duplicate | NVD API, keyword "duplicate of" | Measured: 1,610 NVD records (e.g. "Reason: This candidate is a duplicate of CVE-1999-1395") | Rejected → canonical CVE | Via the canonical CVE | Yes | No (the rejected stub has no description) | Public API |
| syzbot (Linux kernel) | https://syzkaller.appspot.com/upstream/fixed?json=1 | Measured: 7,524 fixed upstream bugs **with fix-commit hashes** in JSON. Bug pages carry a "Duplicate bugs (N)" section; the HTML has it, the JSON lacked a dup field. Total dup count not measured because of HTTP 429. | Fix commits, crash reports, `#syz dup:` | **Yes** | Yes (HTML) | **No** (machine crash titles and stacks) | Public; rate limited |
| OSS-Fuzz / ARVO / CyberGym | ARVO https://github.com/n132/ARVO-Meta (EuroS&P 2026; Docker images for the vulnerable and fixed version plus PoC); CyberGym https://github.com/sunblaze-ucb/cybergym (1,507 vulnerabilities across 188 projects, arXiv 2506.02548) | — | PoC, fix commit, crash output | **Yes, verifiable by re-running the PoC** | ClusterFuzz/tracker duplicates exist; scale UNVERIFIED | No (fuzzer reports; CyberGym adds generated descriptions) | BSD-2 / Apache-2.0 |
| CVEfixes | https://github.com/secureIT-project/CVEfixes, Zenodo 10.5281/zenodo.4476563 | v1.0.8 (to 2024-07-23): 12,107 fix commits in 4,249 projects, 11,873 CVEs (README) | CWE, method/file diffs | Yes | No | No (NVD text) | Repo license NOASSERTION |
| MoreFixes | https://github.com/JafarAkhondali/Morefixes, Zenodo 20776007 (dump 2026-06-20) | Size UNVERIFIED. The README says to use a fix `score` above ~65. | Fix-confidence score | Yes | No | No | NOASSERTION |
| BigVul, ReposVul, Project KB, VulnCode-DB | BigVul https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset (MIT); ReposVul https://github.com/Eshe0922/ReposVul (ICSE'24, arXiv 2401.13169); Project KB https://github.com/SAP/project-kb (Apache-2.0, statements mapping vulnerabilities to fix commits); VulnCode-DB https://github.com/google/vulncode-db (**archived**) | Sizes UNVERIFIED (not re-checked) | CVE ↔ fix-commit mappings | Yes | No | No | As listed |
| Huntr disclosures | huntr.com; 418sec/huntr (272★, stale since 2023) | 1,023 PyPI and 593 Packagist OSV entries reference huntr (measured) | — | Often (reports link fix commits; UNVERIFIED at scale) | Public duplicate status UNVERIFIED | Yes | ToS; Apache no longer accepts huntr reports |

---

## 3. Best ground-truth sources for evaluating duplicate confirmation (ranked)

1. **Chromium plus Firefox security duplicates (Atefi figshare CSV as the label backbone, plus a live tracker crawl for full text and fix commits).**
   - It is the only source at the thousands scale that has human-written external reports, explicit duplicate→original links resolved through chains, and an original that was FIXED.
   - Usable pairs: 1,900 external Chromium duplicates and 364 external Firefox duplicates. The licence is CC BY 4.0.
   - Duplicates often come from different reporters ("independent rediscovery"), so the texts differ, which is exactly the hard case.
   - Cost: Chromium full text needs per-issue scraping of an undocumented endpoint, and you have to map commits through footers.

2. **Mozilla Bugzilla live REST API.**
   - 1,335 public duplicate security bugs; 947 of the 1,096 originals are FIXED.
   - Clean `dupe_of` field, an official API, and coverage through 2026, which matters for testing on the AI-era report mix.
   - Filter out fuzzer and crash-signature reports to keep human prose. Mozilla commits cite bug numbers (convention, not verified here).

3. **HackerOne disclosed duplicates with `original_report_id`.**
   - This is the exact target domain: reporter-written URL, payload and steps, with the program's own duplicate decision.
   - It is small: about 113–116 pairs where both sides are public. Fix commits exist only for OSS programs (curl, Nextcloud, Kubernetes, Brave, Weblate, Paragonie), and the licence is unclear.
   - Best used as a realistic held-out test set, not for training. Get it from the HF snapshot plus the live JSON endpoint.

4. **GitLab gitlab-org/gitlab public HackerOne issues.**
   - 1,212 closed issues, each embedding the reporter's text and a HackerOne Analyst Summary. Only 19 explicit `closedAsDuplicateOf` pairs.
   - Value: a near-perfect demo corpus for a GitLab PSIRT application. It also supplies hard negatives (same feature area, different CVE or fix), and positives can be built by linking issue ↔ CVE ↔ patch-release post.
   - Weak as a source of duplicate labels on its own.

5. **GHSA "Duplicate Advisory" withdrawals plus OSV alias groups.**
   - About 948 explicit pairs measured in 7 ecosystems, and the OSV schema defines aliases as fixed by a single patch, so fixes can be resolved.
   - Weakness: advisory prose, often near-identical, and this is the territory of the SCP 2025 paper. Good for a sanity baseline and as a source of fix commits, not for the main claim.

6. **syzbot, OSS-Fuzz, ARVO and CyberGym.**
   - Ground truth on the fix side is the strongest of all: a fix commit, plus ARVO's runnable PoC on the vulnerable and fixed builds.
   - The reports are machine-generated, so they do not test whether a model understands human external-behavior descriptions.
   - Best use: validating a "same fix?" oracle component (e.g. does the fix for A stop B's PoC?), not report understanding.

**Suggested evaluation construction:**
- **Positives:** sources 1–3, where the original's fix commit is known.
- **Hard negatives:** same program, same component or CWE, similar text, different fix commits. Mine these from Mozilla/Chromium originals and GitLab HackerOne issues.
- **Report the textual-similarity spread** of the positives (e.g. TF-IDF or embedding cosine) so you can show where retrieval-only methods fail.

**Unverified items:**
- The SCP 2025 dataset link: blocked by paywall and 403s, and no artifact was found on GitHub, Zenodo or the web.
- Current Chromium duplicate totals after 2022.
- syzbot and OSS-Fuzz total duplicate counts (rate-limited).
- Huntr's public duplicate status.
- Sizes of MoreFixes, BigVul and ReposVul.
- The HackerOne HF dataset licence.