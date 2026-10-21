# Independent testing and certification: the plan

People trust Norton, Malwarebytes and the like partly because independent labs test them and give them a seal. Hashling is free, open source and made by one person, so this page sets out honestly what it has today, what each independent test involves, what it costs, and what Hashling has to build first to qualify.

Last checked: October 2026. Fees and rules change, so check each link before acting on it.

## What Hashling already has (free, done)

| Signal | Status |
|---|---|
| Open source, MIT license | Done |
| [Security policy](../SECURITY.md) with private vulnerability reporting | Done |
| [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/0xArx/hashling), published every week | Done |
| GitHub CodeQL code scanning on every change | Done |
| Dependabot alerts and update pull requests, secret scanning with push protection | Done |
| Every GitHub Action pinned to an exact commit, read-only tokens by default | Done |
| Hashling.app signed with an Apple Developer ID and notarized by Apple, on each [release](https://github.com/0xArx/hashling/releases), with SHA-256 checksums | Done (`scripts/release.sh`) |
| EICAR and AMTSO Security Features Check self-test | Done, [results](AMTSO-CHECK.md) |

## Free next steps

### 1. OpenSSF Best Practices badge (free, about an hour)

A self-assessment run by the Linux Foundation's OpenSSF at [bestpractices.dev](https://www.bestpractices.dev/en). You answer about 67 questions (basics, change control, reporting, quality, security, analysis), each with a link to the evidence, and the site gives a "passing" badge.

- **Needs the owner's own login** at bestpractices.dev (sign in with GitHub). Nobody else can do this step.
- Most answers already have evidence in this repo: SECURITY.md, CI, CodeQL, Dependabot, signed releases, the MIT license.
- Gaps to close first: a short CONTRIBUTING.md (how to propose changes and report bugs), and automated tests that run in CI for new features (today CI type-checks and tests the phone encryption).
- **Silver** additionally asks for a governance document, a code of conduct, at least two people who can keep the project going, 80% test coverage and reproducible builds. **Gold** asks for two unrelated major contributors and review of most changes by someone other than the author, which is out of reach for a one-person project.

### 2. Build provenance (free)

GitHub's [artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) prove a release file was built by a given workflow from a given commit (SLSA Build Level 2). Today the notarized app is built on the maintainer's Mac because notarization needs the Developer ID certificate. Moving the build into a GitHub Actions macOS runner (with the certificate and notary key as encrypted secrets) would let each release carry an attestation anyone can check with `gh attestation verify`.

### 3. Branch protection (free, a setting)

Scorecard's "Branch-Protection" and "Code-Review" checks score low while changes go straight to `main`. Protecting `main` (no force pushes, required CI checks, changes through pull requests) raises the score. It also means every change goes through a pull request, which changes how the project is worked on, so it is the owner's call.

## Independent lab tests (paid, need new features first)

### AV-TEST (Germany): macOS test

- **What it tests:** protection against fresh Mac malware, effect on speed, and false alarms, each scored out of 6 ([test plan filed with AMTSO](https://amtso.org/wp-content/uploads/2025/03/AMTSO-Test-Plan-AV-TEST-MacOS_Business_Testing_2025_AMTSO.pdf)). Products run with default settings. Results note whether a sample was caught on access (as it arrives or opens) or by a scan.
- **Seal:** reported as 10 or more of the 18 points earns "AV-TEST Certified" (not confirmed: the certification page was down when checked).
- **How to get in:** AV-TEST picks products by market relevance and vendors can ask to be included. Seal rights, detailed data and retests come with a paid agreement.
- **Cost:** not published, quoted on request. Expect a significant yearly fee.

### AV-Comparatives (Austria): Mac Security Test and Review

- **What it tests:** once a year, about 1,500 Mac malware samples, 1,500 potentially unwanted apps and some Windows samples are copied onto a Mac and run ([2026 report](https://www.av-comparatives.org/tests/mac-security-test-review-2026/)). False alarms and speed are checked too.
- **Hard requirement: real-time protection.** Its award criteria list "real-time protection" alongside high protection, no false alarms and no slowdown ([criteria](https://www.av-comparatives.org/mac-security-review-test-2021/)). An app that scans files a few seconds after they arrive, as Hashling does, does not qualify.
- **How to get in:** vendors apply; the lab chooses based on capacity and demand. Free products are accepted.
- **Cost:** reportedly the public test itself is free and fees are for extra services such as consulting and using the award logo (not confirmed; the fee pages could not be loaded).

### SE Labs (UK)

Runs occasional macOS tests using realistic targeted attacks ([selabs.uk](https://selabs.uk/technology/macos/)). Entry terms and fees are not published.

## AMTSO membership

[AMTSO](https://www.amtso.org) is the industry body that sets the rules for fair antivirus testing. It does **not** certify products. Members help write the testing standard and can opt in as "participants" in tests run under it.

- **Fees** ([2025 agreement](https://amtso.org/wp-content/uploads/2025/01/AMTSO-Membership-Agreement-2025-01.pdf)): a company with under $1M revenue pays $1,000 a year ($500 for the first two years); individual members pay $250.
- **Worth it when:** Hashling is ready to enter a lab test, since participants can see and question how they were tested.

## An independent code audit

[OSTIF](https://ostif.org/get-an-audit/) (Open Source Technology Improvement Fund) arranges security audits of open-source projects by professional firms and publishes the reports.

- **How:** fill in OSTIF's intake form, have an intro call, answer a questionnaire; OSTIF writes the scope, gets bids from audit firms, runs the audit and publishes it after a 90-day fix window.
- **Cost:** first audits typically cost $30,000 to $200,000 (an AWS-funded series averaged about $74,000). OSTIF helps find sponsors such as the Sovereign Tech Agency and the Linux Foundation, but funding is not guaranteed.
- **Before applying:** OSTIF asks projects to have their Scorecard and Best Practices badge in order, so steps 1 to 3 above come first.
- **Audit scope that matters most for Hashling:** the Touch ID approval path (can anything approve a fix without the owner?), the local API and its key, the phone pairing channel, prompt injection through file and web content reaching the AI agent, and the installer.

## What Hashling must build before a lab test makes sense

1. **Real-time, on-access protection.** Use Apple's Endpoint Security framework so a file is checked *before* it opens or runs, and blocked if it is malware, instead of being scanned a few seconds after it lands. This needs Apple to grant the `com.apple.developer.endpoint-security.client` entitlement (a request to Apple, free for Developer Program members, not guaranteed) and a system extension the user approves.
2. **Detection for potentially unwanted apps (adware, bundleware)**, which both big labs count separately.
3. **A clear false-alarm process**, so a lab's clean-file set does not cost points, with a way for anyone to report a wrong detection.
4. **A stable, versioned release cadence**, so a lab can test a fixed version and retest updates.
5. **Funding.** Lab seals, AMTSO membership and an audit all cost money. Ask before paying for any of them.

## Suggested order

1. Best Practices badge (owner signs in at bestpractices.dev).
2. CONTRIBUTING.md, more CI tests, branch protection.
3. Release builds in GitHub Actions with attestations.
4. Apply to OSTIF for a funded audit.
5. Build on-access protection (Endpoint Security), then PUA detection.
6. Join AMTSO and apply to AV-Comparatives (free public test) and AV-TEST.
