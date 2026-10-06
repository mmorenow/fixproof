# Industry and tools report: how platforms and PSIRTs handle duplicate vulnerability reports

Research date: 2026-10-06. Every claim has a citation. I fetched the primary sources unless the line says otherwise. **UNVERIFIED** means I could only see it in a search snippet or a secondary source.

---

## 0. Summary

1. **Everyone defines a duplicate by the fix.** Bugcrowd, Intigriti, Code4rena, Sherlock, YesWeHack, the CVE CNA Rules ("Independently Fixable") and the OSV schema (`aliases`) all use the same test: would one patch fix both reports? Nobody defines it by text similarity.
2. **The deployed tools match on metadata and text, not on the fix.**
   - HackerOne compares keywords, embeddings, a "technical fingerprint" (endpoint, parameter), CWE/CAPEC, payload similarity and metadata.
   - Intigriti uses an XGBoost classifier over submission, program and researcher metadata, "rather than raw text".
   - Bugcrowd matches against "historical data".
   - DefectDojo hashes fields.
   - None of them says it decides "same root cause" from evidence. All of them keep a human as the final decision-maker.
3. **The tools that do check whether a report is real don't check for duplicates.** Elastic's agent (8 stages plus sandboxed reproduction, 85% agreement with humans) and Casco's email triage agent (runs the exploit) both reproduce the bug. Neither source mentions duplicate detection. Detection tools don't reproduce, and reproduction tools don't dedupe.
4. **Real PSIRT runbooks show what humans actually check.** GitLab's HackerOne runbook checks two places: was it already reported on HackerOne, and is there already a GitLab issue? It handles these edge cases explicitly:
   - a mishandled original gets reopened, and the duplicate reporter gets a bounty;
   - a duplicate that shows higher impact gets paid the severity difference;
   - chained bugs are scored per bug.

   GitLab then links the report to the GitLab issue, to a CVE request issue, and through the security release to the fix MR.
5. **AI is making simultaneous duplicates more common.** The Linux kernel now says AI-found bugs "systematically surface simultaneously across multiple researchers, often on the same day." curl closed its bounty on Jan 31, 2026. Google paused OSS VRP product-vulnerability submissions on Oct 1, 2026 (UNVERIFIED secondary source).

---

## 1. Bug bounty platforms

### HackerOne
- **"Duplicate" state and linking.** To close a report as a duplicate, the analyst picks "Close report > Duplicate" and enters the original report ID. HackerOne recommends linking the original "to provide accountability and to account for Reputation." The program can add the second hacker as an external participant on the original, or not. Without being added, the hacker sees only the original's ID, state, title, submission date and severity. ([docs.hackerone.com/…/8514410-duplicate-reports](https://docs.hackerone.com/en/articles/8514410-duplicate-reports))
- **Reputation effects** ([docs.hackerone.com/hackers/reputation.html](https://docs.hackerone.com/hackers/reputation.html)):

  | Duplicate of… | Reputation |
  |---|---|
  | a resolved report, filed before the original was made public | +2 |
  | a report that was resolved before the duplicate was filed | 0 |
  | a resolved report, filed after the original was made public | −5 |
  | an N/A report | −5 |

  The timing relative to fix and disclosure is part of the rule.
- **Duplicate Detection console.** Elasticsearch search across all programs the user can access. It pre-fills searches with host, IP, endpoint, parameters and title terms. The docs describe no similarity ranking, and closing is manual. ([8514430-duplicate-detection](https://docs.hackerone.com/en/articles/8514430-duplicate-detection))
- **Agentic Duplicate Detection** (doc dated Feb 11, 2026) ([13703106](https://docs.hackerone.com/en/articles/13703106-agentic-duplicate-detection)):
  - *Stage 1, candidates:* keyword matching, "semantic similarity", and "technical fingerprinting — … affected endpoints, vulnerable parameters".
  - *Stage 2, comparison:* vulnerability category, targeted component, attack vector and "root cause analysis". The doc states: "Two reports might share a vulnerability type but affect different endpoints—that's not a duplicate."
  - *Stage 3, validation:* the original must have been submitted first, self-closed reports are not used as originals, and resolved reports get special handling.
  - *Scope:* "your program's history".
  - *Output:* a proposed original plus "key similarities". The program can accept or override it.
  - *Explicit non-duplicate:* a regression ("previously fixed but has reappeared") triggers investigation, not a duplicate close.
- **Hai dedup agent blog** (Oct 29, 2025; Pearson & Russchen) ([hackerone.com/blog/smart-deduplication-agentic-ai](https://www.hackerone.com/blog/smart-deduplication-agentic-ai)):
  - Says it "cross-checks incoming reports against known global patterns, using CWE identifiers, CAPEC categories, payload similarities, and metadata correlations".
  - Metrics: median dedup time fell from 94 s to 62 s; "80%+ vulnerability types" covered; "80–95% positive recommendation accuracy with human review in the loop".
  - Humans get "a confidence score and a quick explanation."
  - The blog's "global patterns" framing doesn't match the doc's "your program's history" scope.
- **Hai Triage / Agentic Validation** ([8837878](https://docs.hackerone.com/en/articles/8837878-how-hai-triage-works)): classifies type, severity and assets, and can auto-close as "duplicate, informative, spam, or NA" or request more info. It "does not override analyst judgment on severity, bounty, or report validity." The doc does not disclose the duplicate method or its thresholds.
- HackerOne Triage 101 (Feb 2025) says analysts "spent extensive time reviewing and closing invalid and duplicate reports, and then explaining those decisions," and that Hai is meant to make and justify those calls. ([PDF](https://www.hackerone.com/sites/default/files/2025-02/HackerOne-Triage-101.pdf))

### Bugcrowd
- **Three principles** (Grant McCracken, Jun 29, 2023) ([bugcrowd.com/blog/the-three-principles-of-bug-bounty-duplicates](https://www.bugcrowd.com/blog/the-three-principles-of-bug-bounty-duplicates/)):
  1. "Touch the code (or make a change), pay the bug."
  2. "Similar != same": if it needs a separate change, it's unique.
  3. "Many != systemic."

  Worked examples:
  - 10 SQLi bugs in different queries are not duplicates, because "each requires a unique fix".
  - 15 reflected XSS reports across pages using 3 parameters give about 3 unique findings, *if* each parameter is handled identically across pages.
  - 50 missing-CSRF-token reports count as one systemic issue if a framework-level fix covers them all.
- **Status rules** ([docs.bugcrowd.com/…/submission-status](https://docs.bugcrowd.com/customers/submission-management/submission-status)):
  - The program must name the original.
  - The original can be an issue tracked outside Bugcrowd, but then Bugcrowd "requires a data artifact … to compare against as a Known Issue."
  - The duplicate inherits the original's state.
  - **"A submission cannot be marked as a duplicate if the previous submission is already in a Resolved state."** If it still reproduces, it is a regression and counts as unique.
- **Points:** duplicates earn points only when the original is accepted, P1=10 and P2=5. Duplicate P3/P4 earn none. (Search snippet of Bugcrowd docs; UNVERIFIED in full.)
- **Known-issues sharing:** an opt-in feature shows P1–P4 issues that are triaged, unresolved or informational on the program brief, to reduce duplicates. ([docs](https://docs.bugcrowd.com/customers/submission-management/sharing-known-issues-with-researchers))
- **AI Triage** (Aug 20, 2025): "automatically compares new submissions against historical data with 98% confidence, flagging potential duplicates for follow-up by human experts." The post gives no method and no false-positive/negative rates. ([blog](https://www.bugcrowd.com/blog/bugcrowd-ai-triage-speeds-vulnerability-resolution-elevates-hacker-experience/))

### Intigriti
- **Definition** (Inti De Ceukelaire, Jul 10, 2025): "Submissions can be marked as duplicates if they have the same underlying root cause in the code. When in doubt, ask yourself whether the fix for the first report would have fixed the other report as well." If two fixes are needed, for example on two endpoints, the reports are not duplicates. ([blog](https://www.intigriti.com/blog/business-insights/preventing-the-growing-costs-of-repeat-and-duplicate-bug-bounty-submissions))
  - The same post says 3% of a program's vulnerabilities on average had resurfaced after being fixed. A "Dedupe AI model" scans closed submissions for issues that were never fixed or that came back, and feeds retesting.
- **Knowledge base** (KB page returned 404; content from search snippet, UNVERIFIED): programs can mark internally known issues as duplicates but should "provide context." Intigriti recommends giving triage a known-issues list.
- **Platform AI** (Dec 1, 2025, updated Aug 8, 2026) ([blog](https://www.intigriti.com/blog/news/how-ai-is-leveraged-to-enhance-the-intigriti-platform)):
  - "Dupe detection" is a self-hosted **XGBoost binary classifier**, claimed 95% accuracy, retrained every 6 months.
  - "Similarity detection" uses "submission, program, and researcher metadata **rather than raw text**".
  - "Final responsibility remains … with human reviewers."
- **Triage Assist** (May 21, 2026): "surfaces likely duplicates by analysing submission content and historical signals." The post says "Triage Assist doesn't decide. It proposes, and humans decide." It gives no metrics. ([blog](https://intigriti.com/blog/product-updates/how-triage-assist-is-raising-the-bar-in-crowdsourced-security))

### YesWeHack
- Researcher guidance: "If you submit two reports on the same endpoint but with only one different parameter, a single patch will likely be sufficient." Researchers are told to check whether a report duplicates one of their own previous reports. ([yeswehack.com/learn-bug-bounty/tips-write-report-bug-bounty](https://www.yeswehack.com/learn-bug-bounty/tips-write-report-bug-bounty))
- I found no formal platform duplicate policy or AI dedup feature. **UNVERIFIED.**

### Synack
- "A dedicated team reviews every vulnerability submission … ensuring that the exploits can be replicated and preventing duplicate submissions." ([synack.com/?p=17370](https://www.synack.com/?p=17370))
- Detailed duplicate rules: **UNVERIFIED** (not found).

### Immunefi
- Projects are prohibited from "Claiming a bug report is a known or duplicate issue **without clear evidence**," and from "Closing a report without providing detailed information and/or evidence." ([immunefi.com/rules](https://immunefi.com/rules/))
- Researchers are prohibited from "Submitting duplicates of your original report … to claim additional rewards."
- So a duplicate call must come with evidence.

### HackenProof
- "Multiple Issues Same Root Cause": a hunter who submits several reports for one root cause (e.g., missing access control) gets the extras closed and loses reputation.
- Root-cause variants added later in comments are ignored. ([docs.hackenproof.com/dualdefense-audit/general-guidelines](https://docs.hackenproof.com/dualdefense-audit/general-guidelines))

### Web3 audit contests (the most precise written duplicate rules I found)
- **Code4rena:** "Findings are duplicates if they share the same root cause. More specifically, if fixing the Root Cause (in a reasonable manner) would cause the finding to no longer be exploitable, then the findings are duplicates."
  - Duplicates get partial or full credit depending on whether they identify the root cause and the maximum impact.
  - "A lack of identification of the root cause is grounds for partial scoring … or invalidating." ([code4rena.com/judging-criteria](https://code4rena.com/judging-criteria))
- **Sherlock:** a potential duplicate must (1) identify the root cause, (2) show at least Medium impact, and (3) give a valid attack path.
  - "Root cause groupings" cover the same logic mistake (e.g., an unsafe uint256→uint128 cast in several places) and the same conceptual mistake.
  - Reentrancy is split into same-function, cross-function, cross-contract, read-only and cross-chain.
  - Front-run and sandwich reports are grouped "by fix" (slippage protection vs commit-reveal).
  - "If the underlying code implementations, impact or fixes are different, then they may be treated separately." ([docs.sherlock.xyz/audits/judging/guidelines](https://docs.sherlock.xyz/audits/judging/guidelines))
  - Sherlock's Audit Engine runs an "AI judge (validity, severity, **deduplication**, known issue check, in-scope check)" before a human Lead Judge reviews it. ([docs.sherlock.xyz/llms-full.txt](https://docs.sherlock.xyz/llms-full.txt))

---

## 2. GitLab (PSIRT / HackerOne process)

Source: [handbook.gitlab.com/…/psirt/runbooks/hackerone-process/](https://handbook.gitlab.com/handbook/security/product-security/psirt/runbooks/hackerone-process/), unless noted.

**Pipeline**
- HackerOne's triage team validates reports first. GitLab "usually trust[s]" that validation but re-validates when impact or severity is unclear.
- Triage priority: S1/P1 first, then "Close duplicate and invalid reports", then oldest first.

**Duplicate procedure**
- "Verify that the issue was not previously reported in HackerOne, **or that an issue does not already exist in GitLab**." So there are two corpora: H1 reports and GitLab issues.
- Set the state to Duplicate and include the original H1 report ID ("it can impact the reporter's reputation"). Use the "01 - Duplicate" common response and **"Include the link to the GitLab issue."**
- By default the duplicate reporter is not added to the original, because the GitLab issue goes public 90 days after the patch.

**Edge cases the runbook spells out**
- A duplicate that exposes a mishandled original (e.g., one closed as Informative) causes GitLab to reopen the original and pay the new reporter a thank-you bounty: $100 for low, or the initial triage bounty for higher severities. The new reporter is also credited in the CVE and the blog post.
- "If the new report demonstrates new and higher impact, we calculate the CVSS score and award to the new reporter the **difference**."
- **Chaining:** the triager computes a CVSS score for each new bug (each gets its own CVE) plus a "vulnerability chaining" score that sets the bounty. Chains that reuse already-disclosed bugs score only the new links.
- Imported a duplicate by mistake: close the issue, the CVE request and the bounty-council threads.
- If PSIRT can't reproduce a report, it doesn't involve the product team: "Without steps to reliably reproduce … it will be difficult to determine the root cause, propose a meaningful fix."

**Linking to issues, CVEs and releases**
- `/h1 import <report>` in Slack creates a confidential GitLab issue. It also creates a placeholder **CVE request issue** in `gitlab-org/cves` and a bug-bounty-council note.
- The tooling is `h1bot`, `h1-gitlab` and `h1-attachments`. ([hackerone-tooling](https://handbook.gitlab.com/handbook/security/product-security/security-platforms-architecture/product-security-engineering/runbooks/hackerone-tooling/))
- Medium/Low reports that HackerOne has triaged are auto-imported and auto-assigned. Labels include `H1-Status::FalsePositive` and `H1-Policy::OOS`.

**CNA work** ([security-engineer runbook](https://handbook.gitlab.com/handbook/security/product-security/psirt/runbooks/security-engineer/), [verifying-security-fixes](https://handbook.gitlab.com/handbook/security/product-security/psirt/runbooks/verifying-security-fixes/))
- Each CVE is YAML in `gitlab-org/cves`, with a CWE (and "Duo is typically pretty helpful at suggesting" it).
- Title format: `${CWE_TITLE} issue in ${COMPONENT} impacts GitLab ${EDITION}`. Titles must be vague enough not to help attackers but "descriptive enough to differentiate between similar vulnerabilities of the same weakness style in the same release."
- A human adds a `description::validated` label. The `cnaworkflow` bot can set `advisory::invalid`.
- `bin/update_cves.rb` and `bin/close_release.rb` close the issues, publish the CVEs and notify HackerOne.

**PSIRT case lifecycle** ([psirt-case-lifecycle](https://handbook.gitlab.com/handbook/security/product-security/psirt/runbooks/psirt-case-lifecycle/))
- Steps: completeness check, then handoff (published non-critical CVE goes to the KEV check and Vulnerability Management), then validate, reproduce, versions, CVSS, CWE, STRIDE.
- **Variant Hunting** runs in parallel with remediation. The PSIRT charter lists "Variant Hunting" and "Remediation Verification: … not easily bypassed" as core duties. ([psirt](https://handbook.gitlab.com/handbook/security/product-security/psirt/))

**pgvector duplicate-issue hackathon** ([gitlab-org/gitlab#468157](https://gitlab.com/gitlab-org/gitlab/-/issues/468157))
- Setup: Vertex AI embeddings over issue title and description, pgvector with the `neighbor` gem, Euclidean distance below 0.3.
- Findings, verbatim:
  - "Just using title gave us better 'related issues' than 'duplicates'"
  - "descriptions can sometimes be non-existent or unclear"
  - "a very big 'context' challenge since keywords for gitlab-ci.yml are regular words"
  - "embeddings seems to work better for grouping similar than finding semantically duplicate issues"
- Related epic [&13474](https://gitlab.com/groups/gitlab-org/-/epics/13474) plans to store Vertex `textembedding-gecko` embeddings in Elasticsearch for duplicate and similar issue search. No shipped status is stated.

---

## 3. Vendors and open-source projects

### Google
- **Chrome VRP FAQ** ([chromium vrp-faq.md](https://chromium.googlesource.com/chromium/src/+/main/docs/security/vrp-faq.md)):
  - "Only the first **actionable** report … In the event of a duplicate submission, the earliest actionable report in the tracker is considered the first report."
  - "Actionable" means a minimized PoC, reproduction steps, or a **symbolized stack trace**.
  - Internal-tool collision: a bug found by Google's tools within 7 days of the report is "known". Bugs in code landed within 7 days are ineligible.
  - **Robots:** "Incoming security reports are automatically checked against our threat model, FAQs and reporting standards," for example rejecting memory-safety reports that lack a symbolized ASAN stack.
  - Full chains: "report each individual bug in the chain as distinct bugs."
- **Other Google programs** (search snippets of bughunters.google.com, a JavaScript single-page app; **UNVERIFIED** verbatim):
  - Mobile VRP: only the first report "received is awarded (provided that it can be fully reproduced)".
  - Android: the "First Actionable Report" is canonical and needs a functional PoC.
  - Policy on actionable vs non-actionable duplicates updated Jan 25, 2024.
- **OSS VRP:** Google paused product-vulnerability submissions from Oct 1, 2026, citing "automated reports that are largely invalid." ([cyberpress](https://cyberpress.org/google-tightens-open-source-bug-bounty-rules/), secondary source, **UNVERIFIED** against primary)
- **Android "Vedette"** (UW iSchool capstone, 2024): "90% of submitted bug reports are unactionable, with many being duplicates." The prototype shows reporters similar past reports before they submit. ([ischool.uw.edu](https://ischool.uw.edu/capstone/projects/2024/vedette-streamlining-bug-report-deduplication-googles-android-security))

### Microsoft MSRC
- "If we receive multiple bug reports for the same issue from different parties, the bounty will be awarded to the first eligible submission."
- The first external report is paid even if Microsoft already knew internally but hadn't fixed it.
- A duplicate with new information "may" receive a differential award. ([msrc/faqs-bounty](https://www.microsoft.com/en-us/msrc/faqs-bounty))
- Variant and bypass rules: not in the FAQ. **UNVERIFIED.**

### Mozilla
- "First reporter-rule (with a **48-hour collision window**)," with exceptions for non-actionable reports. ([mozilla client bug bounty](https://www.mozilla.org/security/client-bug-bounty/))
- Earlier policy used a 72-hour bounty split. ([attackanddefense.dev 2020](https://attackanddefense.dev/bug-bounty/2020/04/23/bug-bounty-2019-and-future.html))

### curl
- **"The end of the curl bug bounty"** (Jan 26, 2026; ended Jan 31) ([daniel.haxx.se](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/)):
  - Confirmation rate fell from over 15% to under 5% in 2025.
  - Reports now go through GitHub Private Vulnerability Reporting or email, with no rewards.
  - Totals: 87 confirmed vulnerabilities, over $100K paid, per the fetch summary. The Register says 78 ([theregister](https://www.theregister.com/2026/01/21/curl_ends_bug_bounty/)). **The numbers conflict; check before citing.**
- **"Death by a thousand slops"** (Jul 14, 2025): a 7-person team; each report "engages 3-4 persons … 30 minutes, sometimes up to an hour or three"; about 20% AI slop; about 5% genuine. ([blog](https://daniel.haxx.se/blog/2025/07/14/death-by-a-thousand-slops/))
- Neither post discusses duplicates. The bottleneck is checking whether a report is valid at all.

### Linux kernel
- ([security-bugs.rst](https://github.com/torvalds/linux/blob/master/Documentation/process/security-bugs.rst))
  - "A significant part of reports are for bugs that have already been fixed," so reports need an exact version or commit.
  - "**If you resorted to AI assistance to identify a bug, you must treat it as public** … bugs discovered this way systematically surface simultaneously across multiple researchers, often on the same day."
  - Similar issues get separate reports unless they would be "fixed all at once by the same commit."
- Kernel CNA: CVEs are assigned per fix and "tracked … by the git commit id of the original fix." ([cve.rst](https://github.com/torvalds/linux/blob/master/Documentation/process/cve.rst))

### Django
- Reports should contain a brief description, a minimal PoC and versions, and no CVSS or lengthy analysis.
- "Wait for a triage result … before submitting further ones," except for issues "clearly and directly related to an already reported finding."
- Bulk reports "may be put on hold." ([django security.txt](https://github.com/django/django/blob/main/docs/internals/security.txt))

### Node.js
- Classes: Vulnerability, Security-interest bug, Common bug, and Invalid ("Cannot be reproduced", not a Node.js defect, excluded by policy). ([SECURITY.md](https://github.com/nodejs/node/blob/main/SECURITY.md))

### Python PSRT
- Reports arrive through GHSA private reporting.
- A bot manages tickets using title tags `[ACCEPTED] [CLOSED] [INVALID] [DUPLICATE] [COMPLETED]`. The duplicate template says the issue is "already being tracked internally."
- Acceptance auto-assigns a PSF CNA CVE ID. ([devguide.python.org/security/psrt](https://devguide.python.org/security/psrt/))

### Apache
- "Please send one plain-text, unencrypted, email for each vulnerability." ([apache.org/security](https://www.apache.org/security/))

### GitHub
- GitHub bounty: "multiple vulnerabilities caused by one underlying issue will only be eligible for one reward." (search snippet; **UNVERIFIED**)
- I couldn't load the GHSA private-reporting docs (404). Whether there is a native "duplicate" close option is **UNVERIFIED**.
- Countly's SECURITY.md (PR #7862, Jul 2026): another instance of a root cause already reported by the same researcher ("the same defective function, check, or pattern, reached through a different parameter, endpoint, or event") is awarded once. Independent discoverers are assessed separately. ([PR](https://github.com/Countly/countly-server/pull/7862))

### CVE Program and OSV (formal counting definitions)
- **CNA Rules v4.2.0** (Aug 25, 2026; parsed from [CVEProject/cve-website cnaRules.json](https://github.com/CVEProject/cve-website/blob/dev/src/assets/data/cnaRules.json)):
  - 4.1.9: to decide whether separate vulnerabilities exist, "consider whether the Vulnerabilities are **Independently Fixable**."
  - 4.1.10: interdependent conditions (e.g., an integer overflow that causes a buffer overflow) are one vulnerability.
  - 4.2.8: residual insecurity from an **incomplete fix** "MAY" get a new CVE or reuse the existing one.
  - 4.2.12: if unsure, assign one ID.
  - 4.2.13: products that share vulnerable code share one CVE.
  - 4.2.16.7: detect duplicate requests made to different CNAs.
  - 4.5.3.6: reject a CVE for "duplicate assignment."
- MITRE counting rule CNT1: "can be fixed independently of the other bugs." ([counting rules](https://cve.mitre.org/cve/list_rules_and_guidance/counting_rules.html))
- **OSV `aliases`:** two records are aliases if "either both vulnerabilities affect the software component or neither do. **A subsequent patch addresses both … (and no others)**." Aliases are symmetric and transitive. `related` covers "similar but completely different" vulnerabilities and is not transitive. ([osv-schema](https://github.com/ossf/osv-schema/blob/main/docs/schema.md))
- So OSV defines a duplicate as same behavior plus same patch, and keeps "related" as a separate relation.

---

## 4. Signals humans use to call a duplicate

| Signal | Who uses or documents it |
|---|---|
| Same fix would remove both / same root cause in code | Bugcrowd, Intigriti, Code4rena, Sherlock, YesWeHack, CNA 4.1.9, OSV aliases |
| Same endpoint + same parameter (and the parameter is handled identically across pages) | Bugcrowd XSS example; HackerOne fingerprint; YesWeHack |
| Different endpoint, same vuln class → **not** a duplicate | HackerOne agentic doc; Bugcrowd SQLi example; Intigriti |
| Same component / host / IP / attack vector | HackerOne console and agentic stage 2 |
| CWE / CAPEC / payload similarity | HackerOne Hai blog; DefectDojo hash fields |
| Same fix commit / security MR | Linux kernel CNA (CVE per fix commit); GitLab (H1 report ↔ issue ↔ CVE ↔ release) |
| Same crash signature (symbolized ASAN stack) | Chrome actionable definition and robots |
| Existing internal tracker issue / known-issues list | GitLab ("issue already exist in GitLab"); Bugcrowd (artifact required); Intigriti; Chrome internal tools within 7 days; MSRC |
| Timestamp order, gated on "actionable" | Chrome, Android, Mozilla (48 h window), MSRC, HackerOne stage 3 |
| Shared logic or conceptual mistake across locations | Sherlock root-cause groupings |

## 5. Edge cases policies address

- **Variants / same class, different location:**
  - Separate if separately fixable: Bugcrowd "Similar != same", Intigriti, HackenProof (only if same root cause), Sherlock.
  - Systemic issues fixed by one framework change are one finding (Bugcrowd CSRF example).
  - Same-reporter variants are folded in: Countly, HackenProof.
- **Bypass / incomplete fix / regression:**
  - Bugcrowd: no duplicating against a Resolved original if it still reproduces.
  - HackerOne agentic: regressions are not auto-closed as duplicates.
  - CNA 4.2.8: an incomplete fix may get a new CVE.
  - Intigriti: 3% of vulnerabilities resurface; the Dedupe model drives retests.
  - GitLab PSIRT checks that fixes are "not easily bypassed."
- **Chained bugs:**
  - GitLab: per-bug CVSS and CVE, plus a chain score for the bounty, with already-disclosed links excluded.
  - Chrome: report each bug separately.
  - Elastic's agent does not handle multi-vulnerability submissions.
- **Same bug on multiple assets/products:**
  - CNA 4.2.13: shared code means one CVE.
  - GitLab: GitLab.com vs self-managed CVSS difference.
  - DefectDojo: an endpoint/service field can split or merge findings.
- **Filed before vs after fix/disclosure:**
  - HackerOne reputation table.
  - Chrome: 7-day internal and trunk windows.
  - Kernel: many reports are for already-fixed bugs.
  - MSRC: internally known but unfixed counts as eligible.
- **Better or later duplicate:**
  - MSRC differential award.
  - GitLab higher-impact difference.
  - Chrome and Mozilla treat "actionable" as what counts as first.
  - Code4rena gives partial credit to duplicates that miss the root cause.
- **Evidence of duplication owed to the reporter:**
  - Immunefi ("clear evidence").
  - Bugcrowd (data artifact for external known issues).
  - HackerOne (limited view of the original).

## 6. What automation exists, and what it does NOT do

| Tool | Does | Explicitly / evidently does not |
|---|---|---|
| HackerOne Agentic Dedup / Hai | Keyword + embedding + endpoint/parameter fingerprint retrieval; LLM compare on category/component/vector/"root cause"; proposes original, similarities, confidence | Doesn't make the final decision; auto-close thresholds not disclosed; treats regressions as investigation rather than duplicate. No documented code-level or fix-level check. |
| Intigriti Dupe/Similarity, Triage Assist | XGBoost on metadata (not raw text); "historical signals" | "Doesn't decide"; no reproduction. |
| Bugcrowd AI Triage | Flags duplicates vs historical data ("98% confidence") | No method or false-positive/negative rates published; human review required. |
| Sherlock AI judge | Dedup + validity + known-issue check for contests | Lead Judge reviews. |
| Chrome robots | Auto-reject against threat model and report standards | Not described as a dedup tool. |
| Elastic AI triage (Aug 4, 2026) | 8-stage analysis, adversarial review, sandboxed reproduction; 85% agreement on 764 reports | No duplicate detection mentioned; no multi-vulnerability or browser reproduction; human makes every call ([blog](https://www.elastic.co/security-labs/ai-vulnerability-triage-bug-bounty-hackerone)) |
| Casco Email Triage (Jul 28, 2026) | Splits a report into claims, maps them to assets, **runs the exploit** | No duplicate handling mentioned ([blog](https://casco.com/blog/introducing-casco-email-triage)) |
| Trail of Bits / OpenAI "Patch the Planet" | "AI-assisted workflows for deduplication, triage, and patching" with human reproduction | Details not public (openai.com returned 403; secondary [csoonline](https://www.csoonline.com/article/4188321/openai-rolls-out-ai-led-push-to-fix-open-source-software-flaws.html)) **UNVERIFIED** |
| DefectDojo | `unique_id_from_tool`, `hash_code` (per-scanner fields such as title/cwe/severity/file_path/line/vulnerability_ids), endpoint matching, legacy | Scanner findings only; exact-field matching; no understanding of human-written reports ([docs](https://docs.defectdojo.com/triage_findings/finding_deduplication/os__deduplication_tuning/)) |
| GitLab pgvector hackathon / epic &13474 | Embedding nearest-neighbour search | Finds "related", not true duplicates. |
| OSS GitHub bots (PRism, Dupliket, Simili-Bot) | LLM/embedding issue dedup ([PRism](https://github.com/danhdox/prism)) | General issues, not security; no verification. |

**Gap these sources show:** none of these tools both finds the candidate original *and* produces evidence that one fix covers both reports. GitLab's own artifacts (H1 report → GitLab issue → security MR → CVE YAML with CWE and versions) are the joined data that such a check would need. Re-running the original's PoC and the new PoC against the patched build would answer "same fix" from external behavior alone. That fits Chrome's "actionable" bar, Bugcrowd's regression rule and CNA 4.2.8.
