# Practitioner pain points in vulnerability-report duplicate detection and validation

Research done 2026-10-06. I read the primary source wherever one was reachable. Claims I could only find in secondary sources are marked **UNVERIFIED**.

---

## Pain 1: The "same fix" test is the industry definition, and text cannot decide it

**What the platforms say a duplicate is:**
- **Bugcrowd, "Three Principles of Bug Bounty Duplicates":**
  - The principles are "Touch the code, pay the bug", "Similar ≠ same" and "Many ≠ systemic". "Many situations require a non-trivial amount of nuance and context."
  - Reflected XSS with the same parameter on many pages is one issue only if a shared backend function handles it. If the pages process the parameter differently, each one is unique.
  - Missing CSRF protection on 50 endpoints is systemic if one framework-level switch fixes all of them. If 45 endpoints are protected and 5 are not, each of the 5 is unique.
  - Many SQL injections in different query contexts usually each need their own fix.
  - A WAF rule does not count as a fix.
  - https://www.bugcrowd.com/blog/the-three-principles-of-bug-bounty-duplicates/
- **Intigriti (Inti De Ceukelaire):** a duplicate shares "the same underlying root cause in the code… ask yourself whether the fix for the first report would have fixed the other report as well." If two endpoints need two fixes, it is not a duplicate. https://www.intigriti.com/blog/business-insights/preventing-the-growing-costs-of-repeat-and-duplicate-bug-bounty-submissions
- **HackerOne agentic duplicate detection docs:**
  - It finds candidates three ways: keyword matching, semantic similarity, and "technical fingerprinting" of endpoints, parameters and exploitation methods.
  - It then compares vulnerability type, target, attack vector and "underlying root cause".
  - "Two SQL injection reports… are NOT duplicates if they affect different API endpoints."
  - It works only against "your program's history".
  - https://docs.hackerone.com/en/articles/13703106-agentic-duplicate-detection
- **Splunk (Gabriel Nitu, 2026-09-01):** "A duplicate must share the same root cause and affected operation." A generic LLM "cannot reliably triage [a report] until you teach it the product: its architecture, documentation, known false positives, duplicate rules…" https://www.splunk.com/en_us/blog/artificial-intelligence/ai-scales-bug-bounty-reports-product-knowledge-scales-triage.html

**Why this is hard:** the deciding fact is how many code changes are needed. External reports describe a URL, a payload and some steps. Telling a shared handler (a duplicate) from separate handlers (not a duplicate) needs knowledge of how the application routes requests to code. No platform describes how it gets that knowledge.

**HackerOne on how the same bug gets described:** "Even when two reports describe the same underlying vulnerability, the language, structure, and evidence rarely line up." https://www.hackerone.com/blog/smart-deduplication-agentic-ai

**GitLab PSIRT runbook:** for permissions bugs, engineers must "check for similar issues in the API, GraphQL, and Elasticsearch… Also check with alternate authentication mechanisms like Deploy Tokens, Deploy Keys, Trigger Tokens." This is manual variant search across surfaces that share one authorization root cause. https://handbook.gitlab.com/handbook/security/product-security/psirt/runbooks/hackerone-process (source: gitlab-com/content-sites/handbook)

## Pain 2: Telling duplicates apart from variants, bypasses of incomplete fixes and regressions

Programs disagree on how to classify these:
- **Dune:** "If you discover a bypass or a variation of a previously reported vulnerability, this will typically be considered part of the same issue and not eligible for an additional full bounty." It may pay smaller rewards for bypasses that need substantially new techniques. https://docs.dune.com/web-app/bug-bounty
- **Bugcrowd and Intigriti:** a separate code change means a unique issue (see Pain 1). That logic makes a fix bypass a new bug.
- **HackerOne:** separates duplicates (the bug is still open or was recently addressed) from regressions (a fixed bug came back, which "requires investigation"). https://docs.hackerone.com/en/articles/13703106-agentic-duplicate-detection
- **Intigriti on recurrence:** about 3% of vulnerabilities resurface across programs on average, and up to 8% in some programs. The two causes are fixes that were documented but never deployed, and regressions in later releases. https://www.intigriti.com/blog/business-insights/preventing-the-growing-costs-of-repeat-and-duplicate-bug-bounty-submissions
- **Intigriti "Similarity detection":** surfaces past submissions that were resolved or rejected "to enable recurrent retesting". https://www.intigriti.com/blog/news/how-ai-is-leveraged-to-enhance-the-intigriti-platform
- **Hunters are unsure what to do.** An r/bugbounty thread, "Should I submit a fix bypass as a new report?" (around Dec 2025), concerns a patch that left a fallback code path unprotected. Replies split between commenting on the original, filing new, and "HackerOne clearly states that would be a new other report." https://reddit.sentinel-team.org/posts/1rqenzi/snapshots/2026-03-11T09%3A05%3A24.19275Z
- **GitLab rules for edge cases:**
  - If a duplicate shows higher impact, GitLab pays the new reporter the CVSS difference.
  - If a new report reveals that an earlier report was mishandled (for example closed as informative), GitLab reopens the original and pays the new reporter.
  - Source: the GitLab HackerOne runbook above.

## Pain 3: Duplicates against things that are not reports

- **Linux kernel.** Torvalds wrote on LKML on 2026-05-17:
  - "The continued flood of AI reports has basically made the security list almost entirely unmanageable, with enormous duplication due to different people finding the same things with the same tools."
  - Maintainers spend their time saying "that was already fixed a week/month ago" and pointing to the public discussion.
  - Private handling "only makes that duplication worse because the reporters can't even see each other's reports."
  - Sources: https://lkml.org/lkml/2026/5/17/896 (via https://www.linux-magazine.com/Online/News/AI-Flooding-the-Linux-Kernel-Security-Mailing-List/(tagID)/632) and https://www.helpnetsecurity.com/2026/05/18/problems-with-ai-assisted-vulnerability-research/
- **GitLab:** a duplicate check must confirm the issue "was not previously reported in HackerOne, or that an issue does not already exist in GitLab." That is two separate systems to search. https://handbook.gitlab.com/handbook/security/product-security/psirt/runbooks/hackerone-process
- **Intigriti:** duplicates are closed against "known issues, such as findings documented in penetration test reports that you have shared." https://kb.intigriti.com/en/articles/10335710-intigriti-triage-standards (seen via search snippet only)
- **Microsoft (2019):** previously paid 10% for "internally known" bugs. It now pays the first external reporter the full award, but "no change… regarding duplicate external reports." https://www.microsoft.com/en-us/msrc/blog/2019/04/microsoft-bounty-program-updates-faster-bounty-review-faster-payments-and-higher-rewards

## Pain 4: AI-convergent duplicate floods (the 2026 shift)

The problem moved from "slop" to many people finding the same real bugs.

**Linux kernel:**
- Willy Tarreau: reports went from "2 and 3 per week maybe two years ago… probably 10 a week over the last year… now… around 5-10 per day."
- He also reports "duplicate reports, or the same bug found by two different people using (possibly slightly) different tools," and says "we had to bring in more maintainers."
- https://lwn.net/Articles/1065620/ (via https://simonwillison.net/2026/Apr/3/willy-tarreau/)

**Directus** (CTO Rijk van Zanten, 2026-07-10):
- No report was closed as a duplicate from Jan 2022 to Feb 2026. Since then, about 40% of new reports have been duplicates.
- 230 reports arrived in H1 2026, against a historical 30–40 per year. About 5% were valid, against 35–51% in 2023–25.
- Every report must be checked: "test it against a current version, check whether it is reachable and exploitable, look for existing fixes and duplicate reports, decide whether it's actually a security issue."
- https://directus.com/resources/ai-is-straining-vulnerability-disclosure-for-maintainers

**curl:**
- April 2026: "the time when we suffer from large amounts of AI slop is gone. Now we instead suffer under a massive load of good reports"; one report about every 20 hours. https://lists.haxx.se/pipermail/daniel/2026-April/000153.html
- June 2026: "more than one new report per day… The set of pending reports have a lot of things in common and basically all of them used AI." https://lists.haxx.se/pipermail/daniel/2026-June/000157.html

**Intigriti triager Lennaert Oudshoorn** (2026-05-05): "More duplicates arrive because multiple people are accelerated toward the same findings… The problem has shifted from 'too many bad reports' to 'more people can now produce good-enough research at a higher speed.'" https://www.intigriti.com/blog/business-insights/the-ai-impact-a-triagers-perspective

**CPython:** GitHub security advisories (GHSAs) went from 18 (2024) to 41 (2025) to 175 (2026 so far). https://hugovk.dev/blog/2026/security-line-goes-up/

**Screenly:** 331 reports and 39 confirmed in under 6 months, with "a huge proportion as duplicates"; the team built custom triage tooling. Source is RedMonk only, **UNVERIFIED** at the primary source. https://redmonk.com/kholterhoff/2026/05/05/ai-slop-vulnerability-treadmill/

## Pain 5: Validation and reproduction cost (validity, not duplicates)

**curl:**
- "Every report thus engages 3-4 persons. Perhaps for 30 minutes, sometimes up to an hour or three. Each."
- About 20% of 2025 submissions were AI slop, and about 5% were valid.
- Request to HackerOne: "Offer us more tools and knobs to tweak, to save us from drowning."
- https://daniel.haxx.se/blog/2025/07/14/death-by-a-thousand-slops/

**curl bounty end (Jan 2026):**
- The confirmed-vulnerability rate fell from more than 15% to under 5%. The aim is to "remove the incentive for people to submit crap."
- https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/ and https://www.theregister.com/2026/01/21/curl_ends_bug_bounty/
- The lifetime totals conflict: 87 vulnerabilities and $100K+ (blog) against 78 and $86K (BleepingComputer).
- "10–15 hours/week triaging" appears only in secondary sources: **UNVERIFIED**.

**Bugcrowd "sloptimism":** "Generation got cheap, but validation didn't." The triage queue grew 334% in three weeks in March 2026. Slop has "thin evidence, templated write-ups." Bugcrowd responded with bans, a 30-day suspension after 10 consecutive invalid reports, and identity verification.
- https://www.bugcrowd.com/blog/sloptimism-is-breaking-any-system-built-on-human-validation/
- https://www.bugcrowd.com/blog/bugcrowd-policy-changes-to-address-ai-slop-submissions/

**Intigriti triager:** AI reports "look serious… take a much longer time before they can be dismissed." Hunters paste LLM replies, and "it's the triager that then must… verify its contents, possibly reproduce and test various steps." (Oudshoorn, link above.)

**Seth Larson (PSF):** slop reports "appear at first-glance to be potentially legitimate and thus require time to refute." He asks platforms for rate-limiting, de-attribution of abusers, and limits on new accounts. https://sethmlarson.dev/slop-security-reports

**Policy responses:**
- Node.js: Signal ≥1.0 requirement after receiving more than 30 reports between Dec 15 and Jan 15. https://nodejs.org/en/blog/announcements/hackerone-signal-requirement
- Django: AI disclosure is required, and unverified AI output is closed without response. https://docs.djangoproject.com/en/dev/internals/security/
- GitHub (2026-07-23): PoC required, "theoretical attack scenarios" rejected, Signal gate added. https://www.helpnetsecurity.com/2026/07/23/github-bug-bounty-program-changes/

**GitLab:**
- "If PSIRT cannot reproduce an issue… it will be difficult to determine the root cause, propose a meaningful fix."
- Engineers must not use the reporter's PoC: "Develop an exploit payload that will test the vulnerability while eliminating the risk of a malicious payload."
- A dedicated namespace is used for reproduction.
- Source: GitLab HackerOne runbook above.

**"Just bugs":** most AI-found curl reports "are concluded to be 'just bugs'". The Python Security Response Team (PSRT) sees reports from people "not familiar with a programming language threat model". This means classifying security bugs versus ordinary bugs is part of validation. (curl list posts above; Python claim via search summary of PSF materials, partially **UNVERIFIED**.)

## Pain 6: Volume and time numbers

| Source | Figure |
|---|---|
| HackerOne triage team | "over 4,000 reports per week"; 11-hour average time to first response. https://www.hackerone.com/blog/hackerones-depth-approach-vulnerability-triage-and-validation |
| HackerOne Hai deduplication | 94s → 62s per report; recommendations on 92% of reports; 80–95% positive accuracy. https://www.hackerone.com/blog/smart-deduplication-agentic-ai |
| Intigriti Dupe detection | "95% accuracy", retrained every 6 months; method and metric not described. https://www.intigriti.com/blog/news/how-ai-is-leveraged-to-enhance-the-intigriti-platform |
| Splunk manual triage | 2–3 hours per report, 5–6 hours for complex cases. (Nitu, link above) |
| Bugcrowd, 2016 | 19,574 duplicates of 54,114 submissions (36%); 24,516 invalid. https://www.eweek.com/security/average-bug-bounty-payout-now-over-500-bugcrowd-finds/ |
| Android VRP (Google-sponsored capstone "Vedette") | "90% of submitted bug reports are unactionable, many duplicates"; built a reporter-facing similarity tool. https://ischool.uw.edu/capstone/projects/2024/vedette-streamlining-bug-report-deduplication-googles-android-security |
| HackerOne, March 2026 | 46,947 submissions, +76% YoY, 25% valid. Secondary sources only (danilchenko.dev, sesamedisk): **UNVERIFIED** |
| HackerOne IBB | Paused 2026-03-27; "remediation is now the bottleneck". https://www.csoonline.com/article/4154216/internet-bug-bounty-program-hits-pause-on-payouts-2.html (seen via search) |
| Intel | Paid bounty suspended 2026-09-19. Secondary: https://codeant.ai/blogs/intel-bug-bounty-suspension-ai-slop-triage, **UNVERIFIED** primary |
| Hunter guide | Beginners see 50–80% duplicate or rejected; experienced hunters 20–40%. https://bug-bounties.as93.net/learn/handling-duplicates-rejections-and-disputes (practitioner guide, not data) |

## Pain 7: What hunters dispute (fairness and transparency)

- **USENIX Security 2023** (Akgul et al., Distinguished Paper), "Bug Hunters' Perspectives…":
  - "Too many reports marked as duplicates" ranked as the 4th-largest issue.
  - Interviewees linked duplicates to programs "not patching bugs soon enough" (I=6).
  - "Being added to the report (even without rewards) provides assurance the bug-bounty program managers are not lying" (I=4).
  - 16 of 24 interviewees had disputed a decision, including duplicate status.
  - https://www.usenix.org/conference/usenixsecurity23/presentation/akgul
- **What HackerOne shows a duplicate reporter:** if the reporter is not added to the original, they see only its status, ID, title, date and severity. Whether to share more is the program's choice. https://docs.hackerone.com/en/articles/8514410-duplicate-reports
- **GitLab:** by default does not add duplicate reporters to the original. https://handbook.gitlab.com/handbook/security/product-security/psirt/runbooks/hackerone-process
- **r/bugbounty, ~2025:** a critical account takeover was closed as a duplicate of a Medium report that had sat unresolved in triage for 2 years. "The triager doesn't even have access to the original report to verify," and mediation requests were ignored. https://reddit.sentinel-team.org/posts/1rrn94h/snapshots/2026-03-13T05%3A04%3A27.90038Z
- **WhoDupMe:** a hunter-built tool that queries the HackerOne GraphQL API to find out who submitted the original, which only works once it is resolved. It is a sign of distrust. https://pkg.go.dev/github.com/DreyAnd/WhoDupMe
- **Meta thread (2026-03):** hunters allege silent fixes after N/A closure. One commenter cites about 6% of about 10K reports being paid (**UNVERIFIED**). https://reddit.sentinel-team.org/posts/1rv3yf2/snapshots/2026-03-17T01%3A53%3A56.39581Z

## Pain 8: Automated deduplication can fail badly

- **anthropics/claude-code#35923** (general issue tracker, not vulnerability reports, 2026-03-18):
  - The AI duplicate bot created "a graveyard of valid reports all pointing at each other, with no canonical issue."
  - There were 36+ circular chains, such as #4182 ↔ #5528.
  - Issues auto-locked after 7 days, so false closures could not be appealed.
  - It was closed as not planned.
  - https://github.com/anthropics/claude-code/issues/35923
- **HackerOne and Intigriti** both stress that "final responsibility… will always remain with human reviewers." https://www.intigriti.com/blog/news/how-ai-is-leveraged-to-enhance-the-intigriti-platform

## Pain 9: Chained reports

- **GitLab:** compute a CVSS for each link plus a "vulnerability chaining" CVSS. For chains that reuse disclosed bugs, "only the new vulnerabilities in the chain will be eligible." Deduplication has to happen per link, not per report. https://handbook.gitlab.com/handbook/security/product-security/psirt/runbooks/hackerone-process

## Explicit tooling wishes

| Who | Wish |
|---|---|
| Stenberg (curl) | "more tools and knobs" from HackerOne |
| Larson (PSF) | CAPTCHA and rate limits, public disclosure without a CVE, no attribution for abusers, restrictions on new accounts |
| Torvalds (Linux) | reporters seeing each other's reports, and deduplication before submission |
| Directus | platform features on GitHub to stop repeated submissions |
| Hunters (USENIX 2023; WhoDupMe) | verifiable evidence of the original report |
| CSA research note | structured evidence requirements and sandboxed exploit demonstration. https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-vuln-disclosure-noise-signal-inte/ |

**Related tooling that already exists:**
- **Anthropic `defending-code-reference-harness` triage skill:**
  - Deduplicates in two passes: a deterministic file/line pass, then a semantic "fixing one would fix the other" pass, for example a shared vulnerable helper reported once per call site.
  - Verifiers vote, each checking reachability.
  - It works on scanner findings that already have file paths, not on black-box human reports.
  - https://tessl.io/registry/skills/github/anthropics/defending-code-reference-harness/triage
- **Bugbop:** pre-submission scope check plus a post-submission "AI Triage panel" for duplicates. https://bugbop.com/posts/2026/02/01/ai-pre-submission-check-for-bug-reports
- **Vedette (Android VRP):** reporter-facing similarity check. Link in Pain 6.

---

## Ranked unsolved pains a tool could plausibly address

Each pain is tagged **[DUP]** (duplicates), **[VAL]** (validity or reproduction), or both.

1. **[DUP] Fix-equivalence from black-box reports.** Map each report's endpoint, parameter, method and auth context to the code path that handles it (routes to controller, shared helpers, serializers), then decide whether one fix closes both reports. This is the stated industry test (Bugcrowd, Intigriti, HackerOne, Splunk). Public tools judge similarity on text or on endpoint fingerprints. The Anthropic harness does fix-based grouping only for findings that already carry code locations. The gap is translating "URL plus payload" into "code location" and then grouping by root cause. This was the least-addressed, highest-value gap I found.
2. **[DUP+VAL] Telling duplicate, variant, bypass and regression apart with time-awareness.** Compare a new report against the earlier report's fix (commit or MR), the deployed version, and whether the PoC still works after the fix. The outputs are "duplicate (still open)", "regression", "bypass (incomplete fix)" or "variant (sibling code path)". Programs' policies differ (Dune vs Bugcrowd), so the tool should apply each program's configurable rules. HackerOne names regressions but does not describe any method for detecting them.
3. **[DUP] Cross-source matching.** Match reports against non-report sources: public commits and changelogs ("already fixed a week ago", Torvalds), the issue tracker (GitLab requires both H1 and GitLab issues), advisories (GHSA, OSV), and shared pentest findings. HackerOne's agent searches only program history.
4. **[DUP] Handling clusters in AI-convergent floods.** Group N near-identical real findings (Torvalds, Tarreau, Directus at 40%). Pick a canonical report and the first reporter. Detect when a later duplicate shows higher impact, which earns a payout under GitLab's rule. Flag a mishandled original (GitLab's reopen rule).
5. **[DUP] Explainable, shareable duplicate evidence.** Produce a redacted justification such as "same handler X, same fix commit Y, original filed T", which a program could show a disputing hunter without leaking the original. This answers the transparency complaints in USENIX 2023, the r/bugbounty threads and WhoDupMe.
6. **[DUP] Guardrails for automated deduplication.** Always keep one open canonical issue. Detect cycles in duplicate-of chains. Allow appeals. Show confidence and require human approval. This addresses the claude-code#35923 failure mode, and both platforms insist on a human in the loop.
7. **[VAL] Structured claim extraction and reproduction scaffolding.** Parse each report into preconditions, target, payload, expected result and claimed impact. Flag missing PoC elements, as GitHub and Bugcrowd now require. Replay the PoC safely in a sandbox; GitLab uses a reproduction namespace and refuses to run reporters' PoCs.
8. **[VAL] Security bug vs ordinary bug, and threat-model checks.** curl's "just bugs" and PSRT's "unfamiliar with the threat model" problems. Partly addressable by encoding each project's threat model as rules.
9. **[DUP] Decomposing chains.** Split a chained report into its links and deduplicate each link separately (GitLab's "only new links eligible" rule).

Items 1–4 are about duplicates and fit an "after retrieval" verification layer best. Items 5–6 are about trust and process and are cheap to build. Items 7–8 are about validity; full automated reproduction would be a large build, but a narrow version for one target app is plausible.