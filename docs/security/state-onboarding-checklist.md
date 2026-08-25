# State Onboarding Security Checklist

Complete before merging a state onboarding changeset
(`db/migrations/<date>-onboard-<state-code>.yaml`). Derived from
`docs/security/2026-08-23_indiana-milestone-security-spec.md` §6.

Attach the completed checklist to the onboarding PR.

## Onboarding security checklist

To be complete before Indiana's `state_profile` row is written. Intended to be carried in the onboarding artifact (IN-1) rather than tracked separately.

**Prerequisites closed**
- [ ] M-5 — signing key rotated out of the repository, no committed default, startup assertion against the historical literal
- [ ] M-3 — authorization codes redeemed atomically and single-use
- [ ] H-1 — encryption context normalization underway with a dated plan (not required complete)

**Certificate**
- [ ] Delivery channel from Indiana DOR to IRS documented, with verification method
- [ ] `cert_expiration_date` set, and shorter than the certificate's own `notAfter`
- [ ] Revocation SLA agreed with Indiana; targeted cache eviction path exists
- [ ] Rotation cadence and owner recorded
- [ ] Production startup assertion that `cert-location-override` is unset

**Profile data**
- [ ] Every URL field `https:` — validated at write and at point of use (IN-5)
- [ ] `state_redirect` rows are the complete and exact set Indiana will redirect to
- [ ] `accepted_only` decided, with rationale recorded (IN-3)
- [ ] `account_id` unique and format-checked
- [ ] `cert_location` resolves at onboarding time, not first export

**Disclosure**
- [ ] Exported XML elements and facts enumerated (IN-6)
- [ ] Enumeration reviewed against the §6103(d) agreement with Indiana
- [ ] `xml-sanitized.excluded-tags` populated in deployed config and tested against real return XML shapes
- [ ] Determination recorded in the onboarding artifact

**Handoff**
- [ ] Indiana confirms no query-string or referrer logging on the landing path (IN-4)
- [ ] Indiana confirms no third-party analytics on the landing path
- [ ] POST-vs-query-parameter handoff decided for this integration

**Review**
- [ ] Onboarding artifact reviewed as code, by someone other than its author
- [ ] Rollback path exercised — `archived = true` verified to fail closed

## Open decision for the milestone owner

This checklist and the changeset template make a reviewed onboarding path *available*.
They do not make it *mandatory* — nothing prevents a direct database insert that skips
both.

Two questions need an owner:

1. Who approves a state onboarding PR, and does it need security review specifically?
2. What prevents or detects an onboarding that bypasses this path — a database
   permission boundary, an audit alert on `state_profile` writes, or a periodic
   reconciliation of live rows against merged changesets?

Until (2) is answered, the control is a convention rather than an enforcement.
