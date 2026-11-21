/*
 * Email Header Analyzer, ruleset 2026-11-21.1 — synthetic tests for the fixes after the owner's independent run.
 *  1. Own domain at a mailbox provider (Google Workspace: mx.google.com; Microsoft 365: *.outlook.com): the provider is the
 *     trust boundary, its Authentication-Results are trusted, no EHA-AUTH-004/005, DMARC read.
 *  2. A forged Authentication-Results naming mx.google.com below the boundary still gives EHA-AUTH-005; without a real
 *     provider result in a trusted position the provider rule does not apply.
 *  3. privaterelay.appleid.com (Apple's own domain) is not a lookalike of Apple (no EHA-LOOK-003).
 * Headers are written for this test: example.com/.org/.net, documentation IPs, provider host names only.
 * Run: node tests/email-header-analyzer-provider-boundary.test.cjs
 */
'use strict';
const path = require('path');
const fs = require('fs');
const DIR = path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/email-header-analyzer');
const E = require(path.join(DIR, 'engine.js'));
E.loadPSL(fs.readFileSync(path.join(DIR, 'public_suffix_list.dat'), 'utf8').split(String.fromCharCode(13)).join(''), { source: 'test', license: 'MPL-2.0' });
const NOW = '2026-11-21T12:00:00Z';
let failed = 0;
const check = (ok, msg) => { console.log((ok ? 'PASS: ' : 'FAIL: ') + msg); if (!ok) { failed++; } };
const ids = r => r.findings.map(f => f.id);
const L = a => a.join('\r\n') + '\r\n\r\nbody line that must be ignored\r\n';

const AR_GOOGLE = 'Authentication-Results: mx.google.com;\r\n       dkim=pass header.i=@example.org header.s=s1 header.b=AbCdEf12;\r\n       spf=pass (google.com: domain of bounce@mail.example.org designates 192.0.2.10 as permitted sender) smtp.mailfrom=bounce@mail.example.org;\r\n       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.org';
const workspace = extraBelow => L([
	'Delivered-To: user1@example.com',
	'Received: by 2002:a05:7022:1234:b0:1aa:bbbb:cccc with SMTP id ab12csp100200dlb; Fri, 20 Nov 2026 09:10:21 -0800 (PST)',
	'X-Received: by 2002:a05:622a:1:b0:2:3 with SMTP id d75a77b69052e-1mr1.38.1795000000000; Fri, 20 Nov 2026 09:10:20 -0800 (PST)',
	'ARC-Seal: i=1; a=rsa-sha256; t=1795000000; cv=none; d=google.com; s=arc-20260327; b=AAAA',
	'ARC-Authentication-Results: i=1; mx.google.com; dkim=pass header.i=@example.org; spf=pass smtp.mailfrom=bounce@mail.example.org; dmarc=pass header.from=example.org',
	'Return-Path: <bounce@mail.example.org>',
	'Received: from mail.example.org (mail.example.org. [192.0.2.10])\r\n        by mx.google.com with ESMTPS id d75a77b69052e-1si2.379.2026.11.20.09.10.19\r\n        for <user1@example.com>\r\n        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);\r\n        Fri, 20 Nov 2026 09:10:20 -0800 (PST)',
	'Received-SPF: pass (google.com: domain of bounce@mail.example.org designates 192.0.2.10 as permitted sender) client-ip=192.0.2.10;',
	AR_GOOGLE
].concat(extraBelow || [], [
	'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=s1; h=From:To:Subject:Date; bh=AAAA; b=AbCdEf12',
	'From: Example News <news@example.org>',
	'To: user1@example.com',
	'Subject: Weekly update',
	'Date: Fri, 20 Nov 2026 17:10:18 +0000',
	'Message-ID: <20261120171018.1@mail.example.org>',
	'MIME-Version: 1.0'
]));

// 1a. Google Workspace with own domain
let r = E.analyze(workspace(), { own: 'example.com', now: NOW });
check(r.path.providerBoundary && r.path.providerBoundary.host === 'mx.google.com' && r.path.providerBoundary.provider === 'Google', 'Workspace: trust boundary is mx.google.com (mailbox provider for your domain)');
check(r.path.hops[r.path.boundaryIndex].by.host === 'mx.google.com', 'Workspace: boundary hop is the mx.google.com line');
check(!ids(r).includes('EHA-AUTH-004') && !ids(r).includes('EHA-AUTH-005'), 'Workspace: no EHA-AUTH-004/005 (found: ' + ids(r).join(', ') + ')');
check(r.auth.effective.dmarc && r.auth.effective.dmarc.result === 'pass', 'Workspace: trusted DMARC pass is read');
check(ids(r).every(x => ['high', 'medium'].indexOf(E.DEF[x][0]) < 0), 'Workspace: no high or medium finding on an ordinary message');
let ex = E.exportReport(r, { timestamp: NOW });
check(ex.markdown.includes('Trust boundary: mx.google.com (mailbox provider for your domain).') && JSON.parse(ex.json).path.providerBoundary.host === 'mx.google.com', 'Workspace: export states the provider boundary');
const app = fs.readFileSync(path.join(DIR, 'app.js'), 'utf8');
check(app.includes("'Trust boundary: ' + P.providerBoundary.host + ' (mailbox provider for your domain). '"), 'page shows the provider boundary in the trust explanation');
// 1b. same message without own domain, and with own=gmail.com: unchanged behaviour, no provider label needed
const r0 = E.analyze(workspace(), { now: NOW });
check(!r0.path.providerBoundary && r0.auth.effective.dmarc && r0.auth.effective.dmarc.result === 'pass' && !ids(r0).includes('EHA-AUTH-004'), 'no own domain: provider assumed from the top line as before');

// 1c. Microsoft 365 with own domain
const m365 = L([
	'Received: from AM9PR01MB1234.eurprd01.prod.outlook.com (2603:10a6:20b:100::10) by AM9PR01MB5678.eurprd01.prod.outlook.com with HTTPS; Fri, 20 Nov 2026 17:20:05 +0000',
	'Received: from AM6PR01CA0001.eurprd01.prod.outlook.com (2603:10a6:20b:200::11) by AM9PR01MB1234.eurprd01.prod.outlook.com (2603:10a6:20b:100::10) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8000.10; Fri, 20 Nov 2026 17:20:04 +0000',
	'Received: from AM2PEPF00000001.eurprd01.prod.outlook.com (2603:10a6:20b:300::22) by AM6PR01CA0001.outlook.office365.com (2603:10a6:20b:200::11) with Microsoft SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8000.11 via Frontend Transport; Fri, 20 Nov 2026 17:20:04 +0000',
	'Authentication-Results: spf=pass (sender IP is 192.0.2.20) smtp.mailfrom=mail.example.org; dkim=pass (signature was verified) header.d=example.org;dmarc=pass action=none header.from=example.org;compauth=pass reason=100',
	'Received-SPF: Pass (protection.outlook.com: domain of mail.example.org designates 192.0.2.20 as permitted sender) receiver=protection.outlook.com; client-ip=192.0.2.20; helo=mail.example.org; pr=C',
	'Received: from mail.example.org (192.0.2.20) by AM2PEPF00000001.mail.protection.outlook.com (10.167.16.1) with Microsoft SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8000.12 via Frontend Transport; Fri, 20 Nov 2026 17:20:03 +0000',
	'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=s1; h=From:To:Subject:Date; bh=AAAA; b=AbCdEf12',
	'From: Example Billing <billing@example.org>',
	'To: User One <user1@example.com>',
	'Subject: Invoice',
	'Date: Fri, 20 Nov 2026 17:20:00 +0000',
	'Message-ID: <a1b2c3@mail.example.org>',
	'MIME-Version: 1.0'
]);
r = E.analyze(m365, { own: 'example.com', now: NOW });
check(r.path.providerBoundary && r.path.providerBoundary.provider === 'Microsoft' && /\.outlook\.com$/u.test(r.path.providerBoundary.host), 'M365: trust boundary is the Microsoft provider (' + (r.path.providerBoundary && r.path.providerBoundary.host) + ')');
check(r.path.hops[r.path.boundaryIndex].by.host === 'AM2PEPF00000001.mail.protection.outlook.com', 'M365: boundary hop is the protection.outlook.com line');
check(!ids(r).includes('EHA-AUTH-004') && !ids(r).includes('EHA-AUTH-005') && r.auth.effective.dmarc && r.auth.effective.dmarc.result === 'pass', 'M365: trusted DMARC pass, no EHA-AUTH-004/005 (found: ' + ids(r).join(', ') + ')');

// 2a. forged result naming mx.google.com below the boundary: still EHA-AUTH-005, real results still used
const forged = ['Received: from [192.0.2.99] (helo=sender.example.net) by mail.example.org with esmtp; Fri, 20 Nov 2026 17:10:10 +0000', 'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=ceo@example.com; dmarc=pass header.from=example.com'];
r = E.analyze(workspace(forged), { own: 'example.com', now: NOW });
check(ids(r).includes('EHA-AUTH-005'), 'forged mx.google.com result below the boundary: EHA-AUTH-005 kept');
check(r.auth.results.filter(a => a.authservId === 'mx.google.com' && !a.trusted).length === 1 && r.auth.effective.dmarc.result === 'pass', 'forged result untrusted; the real provider result above it stays trusted');
// 2b. only a forged lower result, no real provider result in a trusted position: the provider rule does not apply
const onlyForged = L([
	'Delivered-To: user1@example.com',
	'Received: by 2002:a05:7022:1234:b0:1aa:bbbb:cccc with SMTP id ab12csp100201dlb; Fri, 20 Nov 2026 09:10:21 -0800 (PST)',
	'Received: from mail.example.net (mail.example.net. [198.51.100.7]) by mx.google.com with ESMTPS id x1si2 for <user1@example.com>; Fri, 20 Nov 2026 09:10:20 -0800 (PST)',
	'Received: from [203.0.113.5] by mail.example.net with esmtp; Fri, 20 Nov 2026 17:10:10 +0000',
	'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=it@example.com; dkim=pass header.i=@example.com; dmarc=pass header.from=example.com',
	'From: IT Support <it@example.com>',
	'To: user1@example.com',
	'Subject: Password expires today',
	'Date: Fri, 20 Nov 2026 17:10:09 +0000',
	'Message-ID: <x1@mail.example.net>'
]);
r = E.analyze(onlyForged, { own: 'example.com', now: NOW });
check(!r.path.providerBoundary && ids(r).includes('EHA-AUTH-005') && ids(r).includes('EHA-AUTH-004'), 'only a forged lower mx.google.com result: no provider boundary, EHA-AUTH-004 and EHA-AUTH-005 (found: ' + ids(r).join(', ') + ')');

// 3. Apple private relay address
const relay = L([
	'Received: from mail.example.org (mail.example.org [192.0.2.30]) by mx.example.com (Postfix) with ESMTPS id 4AbC; Fri, 20 Nov 2026 17:30:02 +0000 (UTC)',
	'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=bounce@example.org; dkim=pass header.d=example.org; dmarc=pass header.from=example.org',
	'From: Example Shop <shop_at_example_org_abcd@privaterelay.appleid.com>',
	'To: user1@example.com',
	'Subject: Your order',
	'Date: Fri, 20 Nov 2026 17:30:00 +0000',
	'Message-ID: <o1@example.org>'
]);
r = E.analyze(relay, { own: 'example.com', now: NOW });
check(!ids(r).includes('EHA-LOOK-003'), 'privaterelay.appleid.com is not a lookalike (found: ' + ids(r).join(', ') + ')');
check(E.BRANDS.find(b => b.name === 'Apple').domains.join() === 'apple.com,icloud.com,me.com,appleid.com', 'Apple domains: appleid.com added, nothing else changed');
r = E.analyze(relay.replace('privaterelay.appleid.com', 'appleid-support.example.net').replace('Example Shop', 'Apple Support'), { own: 'example.com', now: NOW });
check(ids(r).includes('EHA-FROM-002'), 'a display name claiming Apple on a foreign domain is still flagged');
check(E.MAILBOX_PROVIDERS.length === 2 && E.RULESET === '2026-11-21.1', 'provider list stays short (Google, Microsoft); ruleset 2026-11-21.1');
console.log(failed ? failed + ' check(s) failed' : 'PASS: provider trust boundary and Apple relay checks');
process.exit(failed ? 1 : 0);
