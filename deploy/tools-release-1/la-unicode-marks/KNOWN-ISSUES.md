# Known issue: Firefox network verification

Status: **UNVERIFIED, explicitly accepted by the owner for this closed-staging installation.**

Firefox D14 LA01–LA10 passed functionally without request interception. The Worker
processed the frozen cases successfully. This run does not verify the assertion
that no network requests occur and must not be described as Firefox network
privacy certification. The prior HTTPS interception/importScripts failure remains
a test-transport limitation; no transport repair was attempted in this execution.

Chromium and WebKit each passed all ten LA D14 cases with interception enabled.
Exactly one acceptance pass per browser was run after installation. No repetitions,
performance measurements or new audits were performed. Original case expectations
remain frozen; only the owner's explicit Firefox network exception applies.
