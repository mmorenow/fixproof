# Academic survey: deciding whether two vulnerability reports describe the same vulnerability

Compiled 2026-10-06. I read the full text of 16 papers (PDFs pulled from arXiv/USENIX and searched for limitations, threats to validity and future work); those are marked **[read]**. Entries marked **[abstract]** were checked only at abstract or metadata level. Semantic Scholar rate-limited most queries, so most discovery ran through arXiv search and web search.

---

## (a) Annotated bibliography

### Theme 1. Duplicate and related vulnerability records, CVE-to-patch linking, cross-database inconsistency

1. **Dong, Guo, Chen, Xing, Zhang, Wang. "Towards the Detection of Inconsistencies in Public Security Vulnerability Reports." USENIX Security 2019.** https://www.usenix.org/conference/usenixsecurity19/presentation/dong [abstract]
   VIEM finds inconsistent affected-version information between NVD, CVE summaries and the reports they reference. Only 59.82% of reports or summaries strictly matched NVD across 78,296 CVEs. Relevance: even "the same vulnerability" across sources disagrees on basic facts, so any matcher that keys on version or product fields inherits this noise.

2. **Tan et al. "Locating the Security Patches for Disclosed OSS Vulnerabilities with Vulnerability-Commit Correlation Ranking" (PatchScout). CCS 2021.** Metadata confirmed via Semantic Scholar. [abstract]
   This is the canonical work that ranks candidate commits against a CVE description. It sets up the retrieve-then-verify pattern that a report de-duplicator could copy.

3. **Xu et al. "Tracking Patches for Open Source Software Vulnerabilities" (Tracer). ESEC/FSE 2022.** https://arxiv.org/abs/2112.02240 [abstract]
   Tracks patches across several knowledge sources. It finds up to 273.8% more patches than heuristic approaches.

4. **Hommersom, Sabetta, Coppola, Di Nucci, Tamburri. "Automated Mapping of Vulnerability Advisories onto their Fix Commits in Open Source Repositories." ACM TOSEM (DOI 10.1145/3649590).** https://arxiv.org/abs/2103.13375 [abstract]
   This is the SAP line of work. The paper calls its prototype FixFinder; I did not verify the link to the "Prospector" tool name. It extracts an "advisory record", filters candidates heuristically, then uses interpretable ML ranking: 84.03% top-10 hit rate and 65.06% top-1. Relevance: the advisory-record extraction step resembles structuring an external-behavior report.

5. **Dunlap, Lin, Enck, Reaves. "VFCFinder: Seamlessly Pairing Security Advisories and Patches." arXiv 2311.01532** (venue claimed as AsiaCCS 2024: UNVERIFIED). https://arxiv.org/abs/2311.01532 [abstract]
   Reports 96.6% top-5 recall and says 63% of database reports lack patch links. It backfilled more than 300 fix commits into GHSA.

6. **Li et al. "PatchFinder: A Two-Phase Approach to Security Patch Tracing for Disclosed Vulnerabilities in OSS." ISSTA 2024.** https://arxiv.org/abs/2407.17065 [abstract]
   Uses a hybrid lexical and semantic retriever followed by a fine-tuned re-ranker: Recall@10 80.63%, MRR 0.795, 482 patches confirmed by CNAs. This is explicitly a two-stage pipeline (retrieve, then correlate), the same architecture the user proposes for reports.

7. **Storhaug, Sun, Li. "Favia: Forensic Agent for Vulnerability-fix Identification and Analysis." arXiv 2602.12500, 2026.** https://arxiv.org/abs/2602.12500 **[read]**
   A ReAct agent explores the pre-commit repository and tries to "establish causal alignment between code changes and vulnerability root causes." The most transferable finding is that evaluating against random negatives overstates performance. Against hard, plausible negatives, agents fail through "Superficial Association" (keyword overlap, file names, coarse semantic similarity). Duplicate reports pose the same problem, because candidates are hard negatives by construction.

8. **Zhang et al. "One Is Not Enough: The Untold Story of Multiple Security Patches for One Vulnerability." arXiv 2609.07224, 2026 (DOI 10.1145/3832783.3837455).** https://arxiv.org/abs/2609.07224 [abstract]
   20.6% of CVEs with patches have several security patches, and merging databases raises the count of multi-patch CVEs by 36–55%. Relevance: the rule "same fix means duplicate" is ambiguous when one vulnerability needs a set of fixes.

9. **Song et al. "COMPASS: Predicting the Relationship of Multiple Patches for Vulnerabilities with LLMs." arXiv 2609.39783, 2026.** https://arxiv.org/abs/2609.39783 [abstract]
   Defines a taxonomy of patch relationships (Merge, Mirror, Better Solution, Fixing-of-Fixing, Collaboration, Separation). This vocabulary could also describe relationships between reports: duplicate, variant, incomplete-fix bypass.

10. **Ayala, Tung, Garcia. "Investigating Vulnerability Disclosures in OSS Using Bug Bounty Reports and Security Advisories." arXiv 2501.17748, 2025.** https://arxiv.org/abs/2501.17748 **[read]**
    Studies 3,798 GHSA advisories and 4,033 disclosed huntr/HackerOne OSS reports. Among 250 advisories without a CVE, "duplicate of another advisory" appears as a stated reason (24.4% per Table 9; my text extraction was garbled, so treat the exact percentage as approximately verified). Gives a pipeline view of how bounty reports become advisories and CVEs.

### Theme 2. Root cause, recurring vulnerabilities, crash deduplication

11. **Xiao et al. "MVP: Detecting Vulnerabilities using Patch-Enhanced Vulnerability Signatures." USENIX Security 2020.** https://www.usenix.org/conference/usenixsecurity20/presentation/xiao [abstract]
    A target is flagged only if it matches the vulnerability signature and does not match the patch signature. It found 97 new vulnerabilities and 23 CVEs. Relevance: this is the code-level form of "same root cause, not yet fixed", using the patch as a discriminator.

12. **Tan et al. "Similar but Patched Code Considered Harmful." ICSE 2025.** https://arxiv.org/abs/2412.20740 [abstract]
    Similar-but-patched code causes most clone-detector false alarms. The FVF filter removes 65.1% of false alarms from ReDeBug, VUDDY and MVP. The report-level analogue is Bugcrowd's "similar ≠ same".

13. **Herter, Ahlrichs, Açilan, Horsch. "GPTrace: Effective Crash Deduplication Using LLM Embeddings." ICSE 2026.** https://arxiv.org/abs/2512.01609 **[read]**
    Embeds stack traces and ASan reports with an LLM, then clusters them. Evaluated on more than 300k crashes covering 50 ground-truth bugs (the Igor dataset). It beats stack-hash methods and Igor. Its related-work section notes LLM triage of human-written bug reports as a related problem but does not tackle it.

14. **Al Mamun, Uddin, Xia, Zhang. "Stack Trace-Based Crash Deduplication with Transformer Adaptation" (dedupT). arXiv 2508.19449.** https://arxiv.org/abs/2508.19449 [abstract]
    Uses a language model adapted to stack traces; more than 15% MRR gain over deep-learning baselines.

15. **Wang et al. "Root-Cause-Driven Automated Vulnerability Repair" (Kumushi). arXiv 2605.04251, 2026.** https://arxiv.org/abs/2605.04251 [abstract]
    Argues that developers and LLM agents often patch symptoms rather than root causes, and that oracle-passing ≠ root-cause fix. Relevance: if fixes can be symptom-level, "same fix" can be a weak proxy for "same root cause."

16. **Wang et al. "KernelDiag: Agent-Based Root Cause Diagnosis for Kernel Crashes." arXiv 2607.17722, 2026** and **Kang et al. "AutoCrashFL." arXiv 2510.22530.** [abstract]
    LLM agents that localize the root-cause method from crash artifacts. These are possible building blocks for "map the report to a code location."

### Theme 3. Report quality, validity, reproducibility, bug bounty economics

17. **Mu, Cuevas, Yang, Hu, Xing, Mao, Wang. "Understanding the Reproducibility of Crowd-reported Security Vulnerabilities." USENIX Security 2018.** https://www.usenix.org/conference/usenixsecurity18/presentation/mu **[read]**
    368 memory-error vulnerabilities, 3,600 analyst-hours. Single reports reproduce only 4.5%–43.8% of the time. After aggregating all sources, 95.1% still miss at least one required field. Most common misses: installation and configuration (87%+), trigger method (26.4%), PoC files (11.7%). They "observe useful correlations between 'similar' vulnerability reports, which can provide hints to reproduce the poorly documented ones." This is early evidence that linking related reports helps verification.

18. **Zheng, Zhou, Ahmad, Yao, Liu. "From Reviewers' Lens: Understanding Bug Bounty Report Invalid Reasons with LLMs." IEEE BigData Congress 2025 / arXiv 2511.18608.** https://arxiv.org/abs/2511.18608 **[read]**
    9,942 disclosed HackerOne reports, 1,400 of them invalid. GPT-5, DeepSeek and RoBERTa "over-accept" invalid reports; adding a RAG taxonomy of rejection reasons helps. "Duplicate" is one invalid category. Higher-reputation reporters get more favorable outcomes in borderline cases. Their motivation names duplicate and near-duplicate reports as a persistent burden.

19. **Shafigh, Benatallah, Rodríguez, Al-Banna. "Why Some Bug-bounty Vulnerability Reports are Invalid?" ESEM 2021.** [abstract via Semantic Scholar]
    Out-of-scope is the top invalid reason, followed by false positives. Produces an out-of-scope taxonomy.

20. **Atefi, Sivagnanam, Ayman, Grossklags, Laszka. "The Benefits of Vulnerability Discovery and Bug Bounty Programs: Case Studies of Chromium and Firefox." arXiv 2301.12092 (WWW 2023 per my recollection: UNVERIFIED).** https://arxiv.org/abs/2301.12092 **[read]**
    Collects 25,358 Chromium security reports (3,905 duplicates) and 6,066 Firefox security reports (1,262 duplicates). Duplicates are resolved to originals via the tracker's `MergeInto` field. Collection scripts are public. Used to estimate rediscovery probability, not to build a detector. **This is a ready-made ground-truth source of human-written security duplicates linked to originals and, through them, to fixes.**

21. **Zrahia, Gandal, Markovich, Riordan. "The simple economics of an external shock to a bug bounty platform." Journal of Cybersecurity 2024.** [abstract]
    Bugcrowd data: during COVID, duplicate valid submissions grew significantly. Only the first submission of a distinct vulnerability is paid, so duplicates directly drive hunter economics.

22. **Ayala, Ngo, Garcia. "A Deep Dive Into How Open-Source Project Maintainers Review and Resolve Bug Bounty Reports." IEEE S&P 2025.** https://arxiv.org/abs/2409.07670 [abstract]
    Survey and interviews with huntr maintainers. "Pressure to review" and hunters chasing money or CVEs are the top challenges.

23. **Akgul et al. "Bug Hunters' Perspectives on the Challenges and Benefits of the Bug Bounty Ecosystem." arXiv 2301.04781 (USENIX Security 2023 per my recollection: UNVERIFIED).** [abstract]
    Communication problems (unresponsiveness, disputes) are hunters' biggest challenge. Duplicate disputes are one likely source; I did not check this in the paper.

24. Industry definitions (not academic, cited as the target criterion):
    - Intigriti: duplicate means "same underlying root cause"; ask whether the first fix would have fixed the second. https://kb.intigriti.com/en/articles/4917102-duplicate-related-or-known-vulnerability-reports
    - Bugcrowd: "Similar != same", "Many != systemic". https://www.bugcrowd.com/blog/the-three-principles-of-bug-bounty-duplicates/

### Theme 4. LLM agents for triage, reproduction and PoC generation (2024–2026)

25. **Zhang et al. "BountyBench." arXiv 2505.15216, 2025 (Stanford/Berkeley).** https://arxiv.org/abs/2505.15216 **[read]**
    25 real systems and 40 real bug bounties covering 9 of the OWASP Top 10, with Detect, Exploit and Patch tasks. **Key mechanism:** the "Detect Indicator" counts an exploit as finding a vulnerability if it succeeds on the vulnerable snapshot and fails on that vulnerability's patched snapshot. The indicator therefore "returns the specific vulnerabilities that were detected (e.g. CVE X and Y)." This is "same fix" turned into an executable test and used for attribution. It works on web vulnerabilities such as IDOR, not just memory-safety bugs.

26. **Wang, Shi, He, Cai, Zhang, Song. "CyberGym." ICLR 2026, arXiv 2506.02548.** https://arxiv.org/abs/2506.02548 **[read]**
    1,507 OSS-Fuzz vulnerabilities; the agent writes a PoC from a text description. Success means a sanitizer crash pre-patch and none post-patch. The benchmark is built by deduplicating instances that share a patch commit and have similar stack traces. Critically, agents "inadvertently generate PoCs that trigger sanitizer crashes on the post-patch versions… a different flaw than the one captured by the ground-truth PoC" (759 instances). They found 18 incomplete patches by fuzzy-matching sanitizer reports and then doing manual root-cause confirmation. Lesson: "reproduces a crash" ≠ "reproduces the reported vulnerability," and they needed patch differentials plus manual root-cause checks to tell them apart.

27. **Lee, Zhang, Lu, Zhang. "SEC-bench." arXiv 2506.11791, 2025.** https://arxiv.org/abs/2506.11791 **[read]**
    A multi-agent pipeline reproduces vulnerabilities from reports and generates gold patches for $0.87 per instance. PoC success peaks at 18.0% and patching at 34.0%. Its verifier prompt requires that "error messages and stack traces should match the vulnerability description," a lightweight report-to-execution consistency check.

28. **Zhu et al. "CVE-Bench." arXiv 2503.17332, 2025.** https://arxiv.org/abs/2503.17332 [abstract]
    Critical-severity web-application CVEs run in a sandbox; agents exploit up to 13%.

29. **Liu, Zhao, Xu, Wang. "LLM Agents for Automated Web Vulnerability Reproduction: Are We There Yet?" arXiv 2510.14700, 2025.** https://arxiv.org/abs/2510.14700 **[read]**
    20 agents evaluated, then 80 web CVEs. There is an "execution-to-trigger gap": PoCs execute 25–70% of the time but trigger the vulnerability only 8.8–21.3%. Performance drops more than 33% when authentication information is incomplete. This is the most realistic evidence on reproducing black-box web reports, the bug bounty setting.

30. **Liu et al. "A Dual-Loop Agent Framework for Automated Vulnerability Reproduction" (CVE2PoC). arXiv 2602.05721, 2026.** [abstract]
    82.9% on SecBench.js and 54.3% on PatchEval.

31. **Duy et al. "PoC-Adapt." arXiv 2604.06618, 2026.** **[read, partially]**
    A "Semantic State Differencing Oracle" compares system state before and after the exploit, because exit codes and console output are "highly prone to false positives… LLM hallucinations where the model incorrectly assumes success." Relevant to validating claimed impact in a report.

32. **Nitin, Ray, Zilouchian Moghaddam. "FaultLine." arXiv 2507.15241** and **Desai et al. "PAGENT." arXiv 2604.07624.** [abstract]
    Source-to-sink reasoning for proof-of-vulnerability generation from a report. FaultLine reproduced only 16 of 100 projects, which shows how hard the problem remains.

33. **Simecek et al. "HoF-Bench: Rediscovering Real AI-Discovered CVEs Without Frontier Models." arXiv 2607.27030, 2026.** https://arxiv.org/abs/2607.27030 **[read]**
    The closest thing to a written rubric for vulnerability equivalence: a blinded LLM judge "credits only findings that identify the same code path, root cause, attack condition, and impact" (match, partial, no match, or insufficient evidence). It also deduplicates findings with deterministic rules plus an LLM judge for ambiguous pairs. It concedes both the judge and the deduplication "are automated and have not been human-audited."

34. **Kang, Yoon, Yoo. "Large Language Models are Few-shot Testers" (LIBRO). ICSE 2023.** https://arxiv.org/abs/2209.11515 [abstract]
    Turns general (non-security) bug reports into reproducing tests: 33% on Defects4J.

### Theme 5. Duplicate bug report detection (DBRD) advances and weaknesses

35. **Zhang, Han, Vinayakarao, Irsan, Xu, Thung, Lo, Jiang. "Duplicate Bug Report Detection: How Far Are We?" ACM TOSEM 2023.** https://arxiv.org/abs/2212.00548 **[read]**
    Data age and tracker choice bias reported results. A simple technique (REP or BM25-style) beats recent deep-learning methods on most projects, and a simple production technique (VSCodeBot) matches research tools.

36. **Zhang, Irsan, Thung, Lo. "Cupid: Leveraging ChatGPT for More Accurate Duplicate Bug Report Detection." arXiv 2308.10022** (published version: I believe TOSEM 2024, UNVERIFIED). https://arxiv.org/abs/2308.10022 **[read]**
    The LLM extracts keywords that feed REP: Recall@10 of 0.602–0.654. It explicitly rejects asking the LLM pairwise "are these duplicates?" because pairing against every report is too costly and pairwise scoring ignores the rest of the repository. So the LLM is used only to enrich retrieval, never to adjudicate.

37. **Jahan & Rahman. "Towards Understanding the Impacts of Textual Dissimilarity on Duplicate Bug Report Detection." arXiv 2212.09976 (SANER 2023 per my recollection: UNVERIFIED).** https://arxiv.org/abs/2212.09976 **[read]**
    19–23% of duplicates are textually dissimilar: same root cause, different observed behavior or steps. They often lack expected-behavior or steps-to-reproduce sections. Existing techniques do "significantly poor" on them, and domain embeddings give mixed results.

38. **Mukherjee & Rahman. "Understanding the Impact of Domain Term Explanation on Duplicate Bug Report Detection." EASE 2025.** https://arxiv.org/abs/2503.18832 [abstract]
    Enriching jargon with explanations helps on textually dissimilar duplicates.

39. **Yan, Cooper, Chaparro, Moran, Poshyvanyk. "JANUS." ICSE 2024** and **Cooper et al. "Tango." ICSE 2021.** [abstract]
    Duplicate detection for video-based reports. Relevant because bounty reports often include PoC videos, a signal Zheng et al. 2025 list as unused.

40. **Rosane et al. "Evaluating Fine-tuning Approaches for DBRD." SBES 2025**, **Laney et al. COMPSAC 2025**, and **GitBugs (Patil et al., arXiv 2504.09651).** [abstract]
    Fine-tuning gives "only marginal" gains; GitBugs is a new benchmark dataset. None of these is security-specific.

---

## (b) Open problems the authors state themselves

1. **Text-only judgments miss non-textual evidence.** "Our evaluation relies on text-based similarity and may overlook non-textual cues such as proof-of-concept videos or attachments." The taxonomy covers only Information Disclosure, and the data is only public HackerOne reports. (Zheng et al., arXiv 2511.18608, §IX)
2. **LLMs over-accept.** They fail to flag invalid reports and lean toward acceptance. Reviewer decisions also show reputation bias. (Zheng et al. 2025)
3. **Automated equivalence judges have not been validated.** "The judge and semantic deduplication are automated and have not been human-audited"; same-family stylistic bias "cannot be ruled out"; "the current implementation does not perform cross-task semantic assignment." (HoF-Bench, arXiv 2607.27030, §4.3 and Limitations)
4. **Agents link reports to code by surface similarity.** Failures come from "Superficial Associations… keyword overlap, file names, or coarse semantic similarity without establishing a causal link." Random-negative evaluation "systematically underestimates task difficulty"; "confidence calibration and causal reasoning — rather than deeper search — are the primary limitations." (Favia, arXiv 2602.12500, RQ2)
5. **Reproducing a crash is not reproducing the reported vulnerability.** 759 generated PoCs hit a different flaw. Telling incomplete patches apart from new bugs needed fuzzy sanitizer matching plus manual root-cause analysis. Future work calls for moving beyond memory safety and sanitizers to "logic flaws… web and mobile," which requires "fine-grained oracles." (CyberGym, arXiv 2506.02548, §5–6)
6. **Sanitizer-based oracles stop at C/C++ memory safety.** "Developing additional verification methods beyond sanitizer tools would enable handling… web applications." (SEC-bench, arXiv 2506.11791, Limitations)
7. **Patch-based evaluators are only as good as their task set and need heavy manual setup.** "Evaluators are not absolute… limited to vulnerabilities that have been added to the system"; setup takes "up to tens of hours each." (BountyBench, arXiv 2505.15216, Discussion)
8. **Web reproduction fails at triggering.** There is a large execution-to-trigger gap, sensitivity to authentication information, and binary success metrics that "may miss important aspects." (Liu et al., arXiv 2510.14700, §6 and Threats)
9. **Reports routinely lack what verification needs.** Notably the trigger method and configuration. The authors call for "automated mechanisms to collect information commonly missing in a report." (Mu et al., USENIX Security 2018)
10. **Textually dissimilar duplicates remain unsolved** and "warrant further investigation and more effective solutions." (Jahan & Rahman, arXiv 2212.09976)
11. **DBRD evaluation is biased** by data age and tracker; reported progress may be illusory. (Zhang et al., TOSEM 2023)
12. **Pairwise LLM adjudication is costly** and blind to the rest of the repository. This is why Cupid avoids it. (Cupid, arXiv 2308.10022, §1)
13. **Crash-dedup future work**: more data sources beyond stack traces and ASan reports, and fine-tuning specifically for deduplication. (GPTrace, arXiv 2512.01609, §6)
14. **What makes a vulnerability valid is an open research question** "especially when PoCs are complex in nature or limited information is known." (Ayala et al., arXiv 2501.17748, §5.1)
15. **"Same fix" is ill-defined when one vulnerability has many patches.** 20.6% of patched CVEs have several. (Zhang et al., arXiv 2609.07224)

---

## (c) Gaps I noticed

### Verified absent after searching
Searches used: arXiv for "duplicate vulnerability reports detection bug bounty", "duplicate security bug reports detection vulnerability reports Chromium", "bug bounty duplicate reports empirical HackerOne Bugcrowd ecosystem", "hallucinated vulnerability reports LLM-generated bug bounty submissions detection", "duplicate vulnerability advisories CVE OSV GHSA", "correlating deduplicating security scanner findings SAST DAST"; Semantic Scholar for "duplicate vulnerability reports detection bug bounty" (498 hits, top 15 reviewed); web searches on the same topics.

- **G1. No paper evaluates duplicate detection on human-written security or bug bounty reports.** Every DBRD paper found uses generic bug trackers (Eclipse, Firefox, VSCode, Hadoop and similar), and the known 2025 SCP work uses published advisories. The only dataset of security duplicates with links to originals that I found, Chromium and Firefox `MergeInto` (Atefi et al.), was used for economics, not detection.
- **G2. No paper uses execution evidence to adjudicate an incoming report against prior ones.** The patch-differential idea exists in BountyBench (Detect Indicator), CyberGym (pre/post-patch oracle) and MVP (patch signatures), but always to score agents or find code clones. None uses it as the triage step "replay the new report's PoC against the snapshot with candidate report X's fix applied; if blocked, it is a same-fix duplicate."
- **G3. No benchmark labels report pairs by relationship type** (duplicate, same-class-different-fix, variant or bypass of an incomplete fix, related). Bugcrowd's "similar ≠ same" and "many ≠ systemic" have no academic counterpart. The closest vocabulary is patch-to-patch, not report-to-report (COMPASS's six relationship types).
- **G4. No study of LLM over-acceptance specifically for duplicates.** Zheng et al. show over-acceptance for validity in general, but no paper measures LLM accuracy on duplicate-versus-unique decisions for security reports.

### Did not find, but my search was not exhaustive
- **G5. A human-validated LLM judge for vulnerability equivalence.** HoF-Bench's rubric (code path, root cause, attack condition, impact) is the nearest, and it is unaudited. I found no inter-rater study of human triagers on "same vulnerability?" for bounty reports.
- **G6. Inferring the root cause from external behavior alone** (URL, parameter, payload, response) in black-box web settings. Existing localization work assumes crash artifacts (KernelDiag, AutoCrashFL) or CVE text plus repository access (Favia, PatchFinder).
- **G7. Robustness to adversarial or AI paraphrase.** I found nothing on whether duplicate detectors can be evaded by rewording a known finding (an incentive that Zrahia et al.'s first-reporter-gets-paid economics creates), or on paraphrase inflation from AI-generated reports.
- **G8. De-duplicating unfixed originals.** BountyBench and CyberGym need a fix to exist. When the original report is still open with no patch, which is common in active programs, no paper offers a verification method. Candidate substitutes: a hypothesized minimal fix, or a WAF or feature-flag style mitigation used as a proxy patch.
- **G9. Multimodal security reports.** Video and screenshot PoCs are handled for GUI bugs (JANUS, Tango) but not for security reports (Zheng et al. list this as future work).
- **G10. Cost- and latency-aware triage combining cheap retrieval with expensive verification**, for example spending agent effort only on the ambiguous band of candidates. Cupid gives the cost argument and Favia the two-stage design, but nobody applies this to security report queues.

### Caveats and unverified items
- I could not retrieve the 2025 Science of Computer Programming paper through any tool. It is treated as known prior work from the task description and was not re-verified.
- These venues come from memory and are UNVERIFIED: VFCFinder at AsiaCCS 2024, Atefi et al. at WWW 2023, Akgul et al. at USENIX Security 2023, Jahan & Rahman at SANER 2023, Cupid in TOSEM.
- I did not read the full text of Zhao, Grossklags & Liu, "An Empirical Study of Web Vulnerability Discovery Ecosystems" (CCS 2015), so I cite no duplicate-rate numbers from it.
- curl's bug bounty ending on 2026-01-31 and HackerOne's Internet Bug Bounty pausing submissions on 2026-03-27 come from press and blog sources, not academic ones, for example https://www.bleepingcomputer.com/news/security/curl-ending-bug-bounty-program-after-flood-of-ai-slop-reports/
