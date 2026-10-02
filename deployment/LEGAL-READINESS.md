# Appora legal and operational readiness (India)

Status date: 24 September 2026. This is an engineering compliance register, not legal advice or a government certification.

## Implemented baseline

- Public Terms, Privacy, Developer, Acceptable Use, Copyright, Retention, Grievance, and Security/Legal Request pages.
- Explicit 18+ account confirmation and versioned policy acceptance records.
- Named operator, address, support, privacy, and grievance contacts are production-required settings.
- Developer approval, private identity-document access, administrator review, APK malware scanning, moderation, audit records, soft deletion, and administrator-only permanent deletion.
- Grievance target: acknowledge within 24 hours and resolve within 7 days, with a working GAC appeal link.
- Numeric retention schedule, including 180-day security logs and a 30-day backup rotation target.
- Verify internal legal links and published contact addresses before each release; local test scripts have been removed from the repository.
- Aadhaar is not an accepted verification document; alternative ID types are offered.

## Official framework tracked

- [Information Technology Act, 2000](https://www.indiacode.nic.in/bitstream/123456789/1999/3/A2000-21.pdf), including intermediary due diligence and lawful requests.
- [Information Technology (Intermediary Guidelines and Digital Media Ethics Code) Rules, 2021, updated through 10 February 2026](https://www.meity.gov.in/static/uploads/2026/02/550681ab908f8afb135b0ad42816a1c9.pdf).
- [Digital Personal Data Protection Act, 2023](https://www.meity.gov.in/static/uploads/2024/02/Digital-Personal-Data-Protection-Act-2023.pdf) and [Digital Personal Data Protection Rules, 2025](https://www.meity.gov.in/documents/act-and-policies/digital-personal-data-protection-rules-2025-gDOxUjMtQWa?pageTitle=Digital-Personal-Data-Protection-Rules-2025), including phased commencement.
- [Consumer Protection framework](https://consumeraffairs.nic.in/acts-and-rules/consumer-protection/consumer-protection), including the Act, E-Commerce Rules, misleading-advertisement rules, and [dark-pattern guidelines](https://consumeraffairs.nic.in/sites/default/files/file-uploads/latestnews/central-consumer-protection-authority-dark-patterns-guidelines-watermark-1565354.pdf).
- [Copyright Act, 1957](https://www.indiacode.nic.in/bitstream/123456789/1367/1/a195714.pdf) and applicable trademark, contract, tax, criminal, accessibility, and sector-specific law.
- [CERT-In directions under section 70B](https://www.cert-in.org.in/Directions70B.jsp), including incident reporting, time synchronisation, and log retention duties where applicable.
- [Grievance Appellate Committee](https://gac.gov.in/) appeal mechanism.
- [UIDAI legal framework](https://uidai.gov.in/en/about-uidai/legal-framework/regulations.html): Appora excludes Aadhaar unless the operator later establishes a separately reviewed compliant verification flow.

## Mandatory operator sign-off before launch

1. Replace every example operator/contact value with the registered entity's real legal name, full postal address, and monitored email accounts.
2. Appoint the grievance officer in writing; staff 24-hour acknowledgement and 7-day resolution; keep ticket and decision evidence.
3. Obtain an Indian lawyer's written review of platform classification, Terms, privacy notice, liability, jurisdiction, consumer remedies, copyright workflow, and current commencement dates.
4. Complete a data map and processor register for Supabase, hosting, object storage, email, malware scanning, analytics, logs, and backups; sign required processing/security terms.
5. Implement and rehearse the retention-deletion job, legal holds, account-rights workflow, breach response, CERT-In reporting, disaster recovery, and evidence preservation.
6. Decide whether paid apps, subscriptions, advertising, commissions, or in-app payments will exist. Before enabling them, add pricing, refund, invoicing, GST, payment-provider, and consumer disclosures.
7. Run a documented dark-pattern self-audit and accessibility audit across registration, consent, cancellation, deletion, ranking, reviews, and any future checkout.
8. Confirm every developer app's age rating, permissions, privacy URL, support route, ownership evidence, regulated-sector authorization, and vulnerability response contact.
9. Preserve dated screenshots, test output, policy versions, approvals, training records, incident exercises, vendor reviews, and legal opinions as audit evidence.

## Release gate

Public registration must remain disabled until all nine operator sign-offs have an owner, completion date, and stored evidence. Re-run the legal review whenever law, business model, data use, vendors, countries, payment flow, or moderation practices change.
