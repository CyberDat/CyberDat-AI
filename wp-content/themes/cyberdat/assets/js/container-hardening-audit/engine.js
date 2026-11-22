/*!
 * CyberDat Docker & Kubernetes Hardening Audit Generator — engine, shared by the worker and the Node tests.
 *
 * Contract (enforced by tests):
 *  - static analysis of text only: nothing is built, pulled, deployed or run; no file is changed and no fixed manifest
 *    is generated — the output is a checklist of findings with suggested changes;
 *  - own rules written by CyberDat; not derived from, numbered like or paraphrasing any CIS Benchmark;
 *  - own Dockerfile reader and own YAML subset reader with size, depth, line and time limits; anchors, aliases, tags and
 *    merge keys are refused; Helm templates are refused with a clear error;
 *  - no network, storage, DOM or eval; no regular-expression look-behind; user text matched with Unicode classes and
 *    the u flag; secrets found in files are shown masked in findings and reports.
 * Background reading (referenced by name only, no text copied): Kubernetes documentation (CC BY 4.0) and Docker
 * documentation (Apache-2.0).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module === 'object' && module.exports) { module.exports = api; } else { root.CyberDatContainerAudit = api; }
}(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const ENGINE = '1.0.1';
	const RULESET = '2026-11-18.1';
	const MAX_INPUT_CHARS = 1024 * 1024;
	const MAX_TOTAL_CHARS = 4 * 1024 * 1024;
	const MAX_FILES = 20;
	const MAX_LINES = 20000;
	const MAX_DEPTH = 64;
	const TIME_BUDGET_MS = 10000;

	// id: [severity, title, why it matters, suggested change]
	const DEF = {
		'DF-USER-001': ['high', 'No USER instruction: the container runs as root', 'Without a USER instruction in the final stage the process runs as root inside the container, so any flaw in the application gives root rights in the container.', 'Create an unprivileged user and add USER <name or UID> before CMD/ENTRYPOINT in the final stage.'],
		'DF-USER-002': ['high', 'The final USER is root', 'The last USER instruction switches back to root (or UID 0), so the application runs with root rights inside the container.', 'Make the last USER instruction an unprivileged user; do root-only steps earlier.'],
		'DF-TAG-001': ['medium', 'Base image uses the latest tag', 'latest can point to a different image at every build, so builds are not reproducible and can pick up unreviewed changes.', 'Pin a specific version tag, and preferably a digest (image:tag@sha256:…).'],
		'DF-TAG-002': ['medium', 'Base image has no tag or digest', 'Without a tag the registry default (usually latest) is used, so builds are not reproducible.', 'Pin a specific version tag, and preferably a digest.'],
		'DF-SEC-001': ['high', 'Secret in ENV or ARG', 'ENV values stay in the image and are visible to anyone who can pull it; ARG values remain in the build history. Secrets should never be baked into an image.', 'Remove the value. Pass secrets at run time (orchestrator secrets, mounted files) or use build secrets (RUN --mount=type=secret).'],
		'DF-ADD-001': ['medium', 'ADD downloads from a URL', 'ADD with a URL fetches remote content at build time without integrity checking, which makes builds depend on an unverified source.', 'Download with curl or wget in a RUN step, verify a checksum or signature, then use the file; or COPY a vendored copy.'],
		'DF-PIPE-001': ['high', 'Remote script piped into a shell', 'Piping a downloaded script straight into a shell runs whatever the server returns, with no review and no integrity check.', 'Download the script to a file, verify its checksum or signature, review it, then run it — or use a package from a trusted repository.'],
		'DF-PORT-001': ['medium', 'Remote-administration or daemon port exposed', 'Exposing SSH, Telnet, RDP, VNC or the Docker daemon port suggests remote administration inside the container, which widens the attack surface.', 'Remove the port. Use docker exec or kubectl exec for administration instead of a daemon in the container.'],
		'DF-SUDO-001': ['low', 'sudo used in RUN', 'Build steps already run as the current USER; sudo in an image usually means it is installed and available at run time too.', 'Run root-only steps before switching USER instead of using sudo; do not install sudo in the image.'],
		'DF-HYG-001': ['info', 'ADD used for a local file', 'ADD also extracts archives and accepts URLs, which makes its effect less obvious than COPY.', 'Use COPY for local files; keep ADD only when automatic archive extraction is intended.'],
		'DF-HYG-002': ['info', 'No HEALTHCHECK', 'Without a health check the runtime can only tell whether the process is running, not whether it works.', 'Add a HEALTHCHECK, or rely on orchestrator probes and state that explicitly with HEALTHCHECK NONE.'],
		'DF-HYG-003': ['info', 'apt-get install without --no-install-recommends', 'Recommended packages are installed too, which makes the image larger and adds software you did not ask for.', 'Use apt-get install -y --no-install-recommends and remove /var/lib/apt/lists/* in the same RUN step.'],

		'DC-PRIV-001': ['high', 'Privileged container', 'privileged: true gives the container almost all host capabilities and device access; escaping to the host becomes easy.', 'Remove privileged. Add only the specific capabilities or devices the service needs.'],
		'DC-CAP-001': ['high', 'Dangerous capability added', 'Capabilities such as SYS_ADMIN, SYS_PTRACE, SYS_MODULE, NET_ADMIN or ALL give the container powers close to root on the host.', 'Remove the capability from cap_add, or replace it with a narrower one the service really needs.'],
		'DC-CAP-002': ['low', 'Capabilities are not dropped', 'Containers start with a default set of Linux capabilities that most applications do not need.', 'Add cap_drop: [ALL] and add back only what the service needs.'],
		'DC-ESC-001': ['medium', 'Privilege escalation not blocked', 'Without no-new-privileges, set-user-ID programs inside the container can gain more privileges than the process started with.', 'Add security_opt: ["no-new-privileges:true"].'],
		'DC-RO-001': ['low', 'Root filesystem is writable', 'A writable root filesystem lets an attacker modify binaries and configuration inside the container.', 'Set read_only: true and use tmpfs or volumes for paths that must be writable.'],
		'DC-USER-001': ['high', 'Service runs as root', 'user is set to root (or UID 0), so the process runs with root rights inside the container.', 'Set user to an unprivileged UID:GID, for example user: "10001:10001".'],
		'DC-USER-002': ['low', 'No user set for the service', 'The user comes from the image; many images run as root by default.', 'Set user to an unprivileged UID:GID, or check that the image sets a non-root USER.'],
		'DC-HOST-001': ['high', 'Host network namespace', 'network_mode: host removes network isolation: the container sees and can bind to all host interfaces.', 'Remove network_mode: host and publish only the ports the service needs.'],
		'DC-HOST-002': ['high', 'Host PID namespace', 'pid: host lets the container see and possibly signal or inspect every process on the host.', 'Remove pid: host.'],
		'DC-HOST-003': ['high', 'Host IPC namespace', 'ipc: host shares the host shared-memory and IPC objects with the container.', 'Remove ipc: host.'],
		'DC-SOCK-001': ['high', 'Container runtime socket mounted', 'Access to the Docker or containerd socket is equivalent to root on the host: the container can start new privileged containers.', 'Remove the socket mount. If a tool really needs the API, use a restricted proxy and run it on a separate host.'],
		'DC-PATH-001': ['high', 'Sensitive host path mounted', 'Mounting system directories of the host exposes host configuration, processes or devices to the container and can allow escaping to the host.', 'Remove the bind mount or mount only the specific file or directory needed, read-only.'],
		'DC-SECO-001': ['high', 'Seccomp or AppArmor disabled', 'unconfined turns off the system-call filter or the AppArmor profile that Docker applies by default.', 'Remove the unconfined setting; if a custom profile is needed, write one that allows only the required calls.'],
		'DC-TAG-001': ['medium', 'Image uses the latest tag', 'latest can change at any time, so deployments are not reproducible and can start unreviewed images.', 'Pin a version tag, and preferably a digest.'],
		'DC-TAG-002': ['medium', 'Image has no tag or digest', 'Without a tag the registry default (usually latest) is used.', 'Pin a version tag, and preferably a digest.'],
		'DC-SEC-001': ['high', 'Secret in environment', 'Values in the Compose file end up in version control and in docker inspect output.', 'Move the value to a secrets file or an environment file that is not committed, and reference it (secrets:, env_file or ${VARIABLE}).'],
		'DC-RES-001': ['low', 'No memory or CPU limit', 'Without limits one service can use all memory or CPU of the host and starve the others.', 'Set mem_limit and cpus, or deploy.resources.limits.memory and .cpus.'],
		'DC-PORT-001': ['medium', 'Remote-administration or daemon port published', 'Publishing SSH, Telnet, RDP, VNC or the Docker daemon port makes administration interfaces reachable from the network.', 'Remove the port mapping; administer containers with docker exec instead.'],
		'DC-HYG-001': ['info', 'Port published on all interfaces', 'A mapping without a host address listens on every host interface, including public ones.', 'Bind to a specific address, for example "127.0.0.1:8080:8080", unless the port must be public.'],
		'DC-HYG-002': ['info', 'No healthcheck', 'Without a health check Compose cannot tell whether the service works, only whether it runs.', 'Add a healthcheck (or rely on the image HEALTHCHECK and state that in a comment).'],

		'K8S-PRIV-001': ['high', 'Privileged container', 'A privileged container has almost all host capabilities and device access; escaping to the node becomes easy.', 'Remove privileged: true. Add only the specific capabilities the container needs.'],
		'K8S-ESC-001': ['medium', 'Privilege escalation allowed', 'Unless allowPrivilegeEscalation is false, set-user-ID programs can gain more privileges than the process started with.', 'Set securityContext.allowPrivilegeEscalation: false on the container.'],
		'K8S-CAP-001': ['high', 'Dangerous capability added', 'Capabilities such as SYS_ADMIN, SYS_PTRACE, SYS_MODULE, NET_ADMIN or ALL give the container powers close to root on the node.', 'Remove the capability from capabilities.add, or replace it with a narrower one.'],
		'K8S-CAP-002': ['low', 'Capabilities are not dropped', 'Containers start with a default set of Linux capabilities that most applications do not need.', 'Set securityContext.capabilities.drop: ["ALL"] and add back only what is needed.'],
		'K8S-RO-001': ['low', 'Root filesystem is writable', 'A writable root filesystem lets an attacker modify binaries and configuration in the container.', 'Set securityContext.readOnlyRootFilesystem: true and mount emptyDir volumes for paths that must be writable.'],
		'K8S-USER-001': ['high', 'Runs as root (runAsUser: 0)', 'runAsUser: 0 runs the container process as root.', 'Set runAsUser to a non-zero UID and runAsNonRoot: true.'],
		'K8S-USER-002': ['medium', 'Not required to run as non-root', 'Neither runAsNonRoot: true nor a non-zero runAsUser is set, so the image decides — many images run as root.', 'Set securityContext.runAsNonRoot: true (pod or container) and a non-zero runAsUser.'],
		'K8S-HOST-001': ['high', 'Host network namespace', 'hostNetwork: true removes network isolation: the pod sees all node interfaces and can reach node-local services.', 'Remove hostNetwork; use a Service to expose the pod.'],
		'K8S-HOST-002': ['high', 'Host PID namespace', 'hostPID: true lets the pod see and possibly inspect every process on the node.', 'Remove hostPID.'],
		'K8S-HOST-003': ['high', 'Host IPC namespace', 'hostIPC: true shares the node IPC namespace with the pod.', 'Remove hostIPC.'],
		'K8S-PATH-001': ['high', 'Sensitive hostPath volume', 'Mounting system directories of the node exposes node configuration, processes or devices and can allow escaping to the node.', 'Remove the hostPath volume; use a ConfigMap, Secret, emptyDir or a PersistentVolume instead.'],
		'K8S-PATH-002': ['medium', 'hostPath volume', 'hostPath ties the pod to a node and gives it direct access to the node filesystem.', 'Prefer emptyDir or a PersistentVolume; if hostPath is unavoidable, mount it read-only and as narrowly as possible.'],
		'K8S-SOCK-001': ['high', 'Container runtime socket mounted', 'Access to the Docker, containerd or CRI-O socket is equivalent to root on the node.', 'Remove the socket volume.'],
		'K8S-PORT-001': ['medium', 'hostPort used', 'hostPort opens the port on the node itself and bypasses Service-level controls.', 'Remove hostPort and expose the container through a Service.'],
		'K8S-TAG-001': ['medium', 'Image uses the latest tag', 'latest can change at any time, so rollouts are not reproducible and can start unreviewed images.', 'Pin a version tag, and preferably a digest.'],
		'K8S-TAG-002': ['medium', 'Image has no tag or digest', 'Without a tag latest is used.', 'Pin a version tag, and preferably a digest.'],
		'K8S-SEC-001': ['high', 'Secret value in the manifest', 'Values in env or ConfigMap data are stored in plain text in version control and in the cluster.', 'Store the value in a Secret managed outside the repository (or an external secret store) and reference it with valueFrom.secretKeyRef.'],
		'K8S-SEC-002': ['medium', 'Secret object with values in the file', 'Secret data in a manifest is only base64-encoded, not encrypted; committing it exposes the values.', 'Keep Secret values out of the repository: create them at deploy time or use an encrypted or external secret mechanism.'],
		'K8S-RES-001': ['low', 'No memory or CPU limit', 'Without limits one container can use all memory or CPU of the node.', 'Set resources.limits.memory and resources.limits.cpu (and requests).'],
		'K8S-SA-001': ['low', 'Default service account', 'Pods that use the default service account share its permissions with every other pod in the namespace.', 'Create a dedicated ServiceAccount for the workload and set serviceAccountName.'],
		'K8S-SA-002': ['medium', 'Service account token mounted automatically', 'The API token is mounted into every container even if the application never calls the Kubernetes API.', 'Set automountServiceAccountToken: false on the pod (or on its ServiceAccount) unless the API is needed.'],
		'K8S-SECCOMP-001': ['medium', 'No seccomp profile', 'Without a seccomp profile the container can use every system call the kernel offers.', 'Set securityContext.seccompProfile.type: RuntimeDefault on the pod.'],
		'K8S-SECCOMP-002': ['high', 'Seccomp disabled (Unconfined)', 'Unconfined turns off system-call filtering for the container.', 'Use seccompProfile.type: RuntimeDefault or a Localhost profile.'],
		'K8S-APPARMOR-001': ['low', 'No AppArmor profile', 'On nodes with AppArmor, an explicit profile limits what the container can do with files, mounts and capabilities.', 'Set securityContext.appArmorProfile.type: RuntimeDefault (or the AppArmor annotation on older clusters).'],
		'K8S-APPARMOR-002': ['high', 'AppArmor disabled (Unconfined)', 'Unconfined turns off AppArmor confinement for the container.', 'Use appArmorProfile.type: RuntimeDefault or a Localhost profile.'],
		'K8S-RBAC-001': ['high', 'Wildcard in an RBAC rule', 'A * in apiGroups, resources or verbs grants access to everything in that dimension, including resources added later.', 'List the specific API groups, resources and verbs the subject needs.'],
		'K8S-RBAC-002': ['high', 'Binding to cluster-admin', 'cluster-admin allows every action on every resource; a compromised subject controls the whole cluster (or namespace).', 'Bind a role with only the permissions the subject needs.'],
		'K8S-PROBE-001': ['info', 'No liveness probe', 'Without a liveness probe Kubernetes cannot restart a container that hangs.', 'Add a livenessProbe that checks the application, not just the process.'],
		'K8S-PROBE-002': ['info', 'No readiness probe', 'Without a readiness probe traffic is sent to the pod before it is ready.', 'Add a readinessProbe.']
	};
	const INPUT_ERRORS = {
		'INPUT-HELM': 'This looks like a Helm template ({{ … }}). Templates cannot be audited before rendering. Render it first (for example helm template) and paste the rendered manifests.',
		'INPUT-ANCHOR': 'YAML anchors, aliases, tags and merge keys (&, *, !, <<) are not supported. Expand them and try again.',
		'INPUT-UNKNOWN': 'This is not recognised as a Dockerfile, a Docker Compose file or Kubernetes YAML. Choose the type, or check that the text is complete.'
	};
	const SEV_RANK = { high: 4, medium: 3, low: 2, info: 1 };
	const ADMIN_PORTS = new Set([22, 23, 2375, 2376, 3389, 5900]);
	const DANGEROUS_CAPS = new Set(['ALL', 'SYS_ADMIN', 'SYS_MODULE', 'SYS_PTRACE', 'SYS_RAWIO', 'SYS_BOOT', 'SYS_TIME', 'DAC_READ_SEARCH', 'NET_ADMIN', 'BPF', 'PERFMON', 'MAC_ADMIN', 'MAC_OVERRIDE']);
	const SENSITIVE = ['/etc', '/proc', '/sys', '/dev', '/boot', '/root', '/run', '/var/run', '/var/lib/docker', '/var/lib/kubelet', '/var/lib/containerd'];
	const SOCKET_RE = /(?:docker|containerd|crio|podman|cri-dockerd)\.sock$/u;

	const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
	const arr = v => (Array.isArray(v) ? v : []);
	const nfc = s => String(s).normalize('NFC');
	const isTrue = v => v === true || v === 'true';
	function budget() { const end = Date.now() + TIME_BUDGET_MS; return () => { if (Date.now() > end) { const e = new Error('Processing took longer than ' + (TIME_BUDGET_MS / 1000) + ' seconds and was stopped.'); e.code = 'TIMEOUT'; throw e; } }; }

	// ------------------------------------------------------------------ secrets (masked)
	const SECRET_PATTERNS = [
		['AWS access key ID', /(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}/gu], ['GitHub token', /gh[pousr]_[0-9A-Za-z]{30,}/gu], ['GitLab token', /glpat-[0-9A-Za-z_-]{20,}/gu],
		['Slack token', /xox[abposr]-[0-9A-Za-z-]{10,}/gu], ['Anthropic API key', /sk-ant-[0-9A-Za-z_-]{20,}/gu], ['OpenAI-style API key', /sk-(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{20,}/gu],
		['Google API key', /AIza[0-9A-Za-z_-]{35}/gu], ['Hugging Face token', /hf_[0-9A-Za-z]{30,}/gu], ['JSON Web Token', /eyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{5,}\.[0-9A-Za-z_-]*/gu],
		['Private key', /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/gu], ['Password in URL', /[a-z][a-z0-9+.-]{1,20}:[/][/][^\s:/@]{1,64}:[^\s@/]{1,128}@/giu]
	];
	const TOKEN_CHAR = /[\p{L}\p{N}\p{M}_]/u;
	const mask = v => { const c = [...String(v)]; return c.length <= 8 ? '••••' : c.slice(0, 4).join('') + '… (' + c.length + ' characters)'; };
	const hideAll = v => '•••• (' + [...String(v)].length + ' characters)';
	function entropy(s) { const m = new Map(); for (const ch of s) { m.set(ch, (m.get(ch) || 0) + 1); } let e = 0; for (const n of m.values()) { const p = n / s.length; e -= p * Math.log2(p); } return e; }
	function findSecrets(text) {
		const s = String(text || '');
		const out = [];
		const taken = (a, b) => out.some(x => a < x.end && b > x.start);
		for (const [kind, re] of SECRET_PATTERNS) { re.lastIndex = 0; let m; while ((m = re.exec(s))) { const a = m.index, b = a + m[0].length; if ((a > 0 && TOKEN_CHAR.test(s[a - 1]) && kind !== 'Private key' && kind !== 'Password in URL') || taken(a, b)) { continue; } out.push({ kind, start: a, end: b, shown: kind === 'Private key' ? 'BEGIN … PRIVATE KEY' : kind === 'Password in URL' ? m[0].slice(0, m[0].indexOf('//') + 2) + '…:••••@' : mask(m[0]) }); } }
		const LONG = /[0-9A-Za-z+/=_\-.]{24,}/gu;
		let m;
		while ((m = LONG.exec(s))) {
			const v = m[0], a = m.index, b = a + v.length;
			if (taken(a, b) || (a > 0 && TOKEN_CHAR.test(s[a - 1])) || (b < s.length && TOKEN_CHAR.test(s[b]))) { continue; }
			if (!/[0-9]/u.test(v) || !/[A-Za-z]/u.test(v) || /^[0-9a-fA-F-]+$/u.test(v) || /^(?:https?|www)/iu.test(v) || /^[0-9a-f]{8}-[0-9a-f]{4}-/iu.test(v) || v.includes('/') || entropy(v) < 3.8) { continue; }
			out.push({ kind: 'unrecognized long value', start: a, end: b, shown: mask(v) });
		}
		return out.sort((x, y) => x.start - y.start);
	}
	function maskSecrets(text) { let s = String(text || ''); for (const x of findSecrets(s).sort((p, q) => q.start - p.start)) { s = s.slice(0, x.start) + '[' + x.kind + ': ' + x.shown + ']' + s.slice(x.end); } return s; }
	const SECRET_NAME = /(?:^|[_.-])(?:PASSWORD|PASSWD|PASS|PWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CLIENT_?SECRET|CREDENTIALS?|AUTH_?KEY|SECRET_?KEY)(?:$|[_.-])/iu;
	const NOT_SECRET_NAME = /(?:_FILE|_PATH|_DIR|_ENABLED|_LENGTH|_TTL|_EXPIRY|_EXPIRES|_TIMEOUT|_HEADER|_NAME)$/iu;
	/** Returns masked evidence when name/value look like a secret, otherwise ''. */
	function secretEvidence(name, value) {
		const n = String(name || ''), v = value === null || value === undefined ? '' : String(value);
		if (!v.trim() || /^\$/u.test(v.trim()) || /^(?:true|false|yes|no|on|off|null)$/iu.test(v.trim()) || /^[0-9]{1,5}$/u.test(v.trim())) { return ''; }
		const found = findSecrets(v);
		if (found.length) { return n + ' = [' + found[0].kind + ': ' + found[0].shown + ']'; }
		if (SECRET_NAME.test(n) && !NOT_SECRET_NAME.test(n)) { return n + ' = ' + hideAll(v); }
		return '';
	}

	// ------------------------------------------------------------------ findings
	function finding(id, ctx, line, evidence, extra) {
		const d = DEF[id];
		return Object.assign({ id, severity: d[0], group: d[0] === 'info' ? 'hygiene' : 'security', title: d[1], explanation: d[2], fix: d[3], file: ctx.file, document: ctx.document || 0, object: ctx.object || '', container: '', line: line || 0, evidence: evidence ? maskSecrets(nfc(evidence)).slice(0, 300) : '' }, extra || {});
	}
	function imageTag(ref) {
		const s = String(ref || '').trim();
		if (!s || s.includes('$') || s.includes('{')) { return 'skip'; }
		if (s.includes('@')) { return 'ok'; }
		const last = s.split('/').pop();
		const i = last.lastIndexOf(':');
		const tag = i >= 0 ? last.slice(i + 1) : '';
		if (!tag) { return 'none'; }
		return tag.toLowerCase() === 'latest' ? 'latest' : 'ok';
	}
	const normPath = p => { let s = String(p || '').trim().replace(/[/]+/gu, '/'); if (s.length > 1) { s = s.replace(/[/]+$/u, ''); } return s; };
	function hostPathClass(p) {
		const s = normPath(p);
		if (!s.startsWith('/')) { return ''; }
		if (SOCKET_RE.test(s)) { return 'socket'; }
		if (s === '/') { return 'sensitive'; }
		if (SENSITIVE.some(x => s === x || s.startsWith(x + '/'))) { return 'sensitive'; }
		return 'other';
	}
	const capName = c => String(c || '').trim().toUpperCase().replace(/^CAP_/u, '');

	// ------------------------------------------------------------------ YAML subset reader (shared design with the YARA/Sigma validator)
	const yamlError = (code, line, msg) => { const e = new Error(msg + (line ? ' (line ' + line + ')' : '')); e.code = code; e.line = line; return e; };
	/** Returns { docs: [{ value, line }], lines: Map(path -> line) }. Throws INPUT-YAML / INPUT-ANCHOR. */
	function parseYaml(text, tick) {
		const src = String(text || '').replace(/^\ufeff/u, '');
		const raw = src.split(/\r\n|\r|\n/u);
		if (raw.length > MAX_LINES) { throw yamlError('INPUT-YAML', 0, 'The input has more than ' + MAX_LINES + ' lines'); }
		const lines = new Map();
		const docs = [];
		let cur = [];
		const flush = () => { if (cur.some(l => l.text.trim() && !/^\s*#/u.test(l.text))) { docs.push(cur); } cur = []; };
		raw.forEach((t, i) => { if (/^---\s*(?:#.*)?$/u.test(t) || /^\.\.\.\s*$/u.test(t)) { flush(); } else if (/^%/u.test(t) && !cur.length) { /* directive */ } else { cur.push({ n: i + 1, text: t }); } });
		flush();
		const out = docs.map((d, di) => ({ value: parseDoc(d, di), line: d.length ? d[0].n : 1 }));
		return { docs: out, lines };

		function stripComment(t) {
			let q = '', o = '';
			for (let i = 0; i < t.length; i++) {
				const c = t[i];
				if (q) { o += c; if (c === q) { if (q === '\'' && t[i + 1] === '\'') { o += t[++i]; continue; } q = ''; } else if (q === '"' && c === '\\') { o += t[++i] || ''; } continue; }
				if (c === '#' && (i === 0 || /\s/u.test(t[i - 1]))) { break; }
				if ((c === '\'' || c === '"') && (i === 0 || /[\s:\-[{,]/u.test(t[i - 1]))) { q = c; }
				o += c;
			}
			return o.replace(/\s+$/u, '');
		}
		function parseDoc(docLines, di) {
			const L = docLines.map(l => {
				if (/^ *\t/u.test(l.text) && l.text.trim()) { throw yamlError('INPUT-YAML', l.n, 'Tab characters are not allowed in indentation'); }
				const body = stripComment(l.text);
				return { n: l.n, raw: l.text, body, indent: body.length - body.replace(/^ +/u, '').length };
			});
			let i = 0;
			const skip = () => { while (i < L.length && !L[i].body.trim()) { i++; } };
			const pfx = '/doc' + di;
			skip();
			if (i >= L.length) { return null; }
			const v = block(L[i].indent, pfx, 0);
			skip();
			if (i < L.length) { throw yamlError('INPUT-YAML', L[i].n, 'Unexpected indentation or content'); }
			return v;

			function block(ind, p, depth) {
				if (depth > MAX_DEPTH) { throw yamlError('INPUT-YAML', L[i].n, 'Nesting is deeper than ' + MAX_DEPTH + ' levels'); }
				if (tick) { tick(); }
				skip();
				const line = L[i];
				const t = line.body.trim();
				if (t === '-' || t.startsWith('- ')) { return seq(line.indent, p, depth); }
				if (keyOf(t)) { return map(line.indent, p, depth); }
				i++;
				return scalar(t, line.n, p);
			}
			function keyOf(t) {
				let m;
				if (t[0] === '"' || t[0] === '\'') { const q = t[0]; let j = 1; for (; j < t.length; j++) { if (t[j] === '\\' && q === '"') { j++; continue; } if (t[j] === q) { if (q === '\'' && t[j + 1] === '\'') { j++; continue; } break; } } if (t[j + 1] === ':' && (t.length === j + 2 || t[j + 2] === ' ')) { return { key: unquote(t.slice(0, j + 1), 0), rest: t.slice(j + 2).trim() }; } return null; }
				if ((m = /^([^\s:#'"[\]{},&*!|>%@`][^:#]*?|[^\s:#'"[\]{},&*!|>%@`]?)\s*:(?:\s+(.*))?$/u.exec(t)) && !/^- /u.test(t)) { return { key: m[1].trim(), rest: (m[2] || '').trim() }; }
				return null;
			}
			function map(ind, p, depth) {
				const obj = {};
				for (;;) {
					skip();
					if (i >= L.length) { break; }
					const line = L[i];
					if (line.indent < ind) { break; }
					if (line.indent > ind) { throw yamlError('INPUT-YAML', line.n, 'Unexpected indentation'); }
					const t = line.body.trim();
					if (t === '-' || t.startsWith('- ')) { break; }
					const k = keyOf(t);
					if (!k) { throw yamlError('INPUT-YAML', line.n, 'Expected “key: value”'); }
					if (k.key === '<<') { throw yamlError('INPUT-ANCHOR', line.n, 'Merge keys are not supported'); }
					if (Object.prototype.hasOwnProperty.call(obj, k.key)) { throw yamlError('INPUT-YAML', line.n, 'Duplicate key “' + k.key + '”'); }
					const kp = p + '/' + k.key;
					lines.set(kp, line.n);
					i++;
					let v;
					if (k.rest === '') {
						skip();
						if (i < L.length && (L[i].indent > ind || (L[i].indent === ind && /^- |^-$/u.test(L[i].body.trim())))) { v = block(L[i].indent, kp, depth + 1); } else { v = null; }
					} else if (/^[|>][+-]?[0-9]?$/u.test(k.rest)) { v = blockScalar(k.rest, ind); }
					else { v = scalar(k.rest, line.n, kp); }
					Object.defineProperty(obj, k.key, { value: v, enumerable: true, writable: true, configurable: true });
				}
				return obj;
			}
			function seq(ind, p, depth) {
				const a = [];
				for (;;) {
					skip();
					if (i >= L.length) { break; }
					const line = L[i];
					const t = line.body.trim();
					if (line.indent !== ind || !(t === '-' || t.startsWith('- '))) { if (line.indent > ind) { throw yamlError('INPUT-YAML', line.n, 'Unexpected indentation in a list'); } break; }
					const ip = p + '/' + a.length;
					lines.set(ip, line.n);
					const rest = t === '-' ? '' : t.slice(2).trim();
					if (rest === '') { i++; skip(); a.push(i < L.length && L[i].indent > ind ? block(L[i].indent, ip, depth + 1) : null); continue; }
					if (keyOf(rest)) {
						const col = line.indent + 2 + (t.slice(1).length - t.slice(1).trimStart().length - 1);
						L[i] = { n: line.n, raw: line.raw, body: ' '.repeat(col) + rest, indent: col };
						a.push(map(col, ip, depth + 1));
						continue;
					}
					if (rest === '-' || rest.startsWith('- ')) {
						const col = line.indent + 2;
						L[i] = { n: line.n, raw: line.raw, body: ' '.repeat(col) + rest, indent: col };
						a.push(seq(col, ip, depth + 1));
						continue;
					}
					i++;
					a.push(/^[|>][+-]?[0-9]?$/u.test(rest) ? blockScalar(rest, ind) : scalar(rest, line.n, ip));
				}
				return a;
			}
			function blockScalar(ind0, parentIndent) {
				const keep = ind0.includes('+'), strip = ind0.includes('-'), folded = ind0[0] === '>';
				const parts = [];
				let ind = -1;
				while (i < L.length) {
					const r = L[i].raw;
					if (!r.trim()) { parts.push(''); i++; continue; }
					const n = r.length - r.replace(/^ +/u, '').length;
					if (n <= parentIndent) { break; }
					if (ind < 0) { ind = n; }
					if (n < ind) { break; }
					parts.push(r.slice(ind));
					i++;
				}
				while (!keep && parts.length && parts[parts.length - 1] === '') { parts.pop(); }
				let s = folded ? parts.join('\n').replace(/([^\n])\n(?!\n| )/gu, '$1 ') : parts.join('\n');
				if (!strip) { s += '\n'; }
				return s;
			}
		}
		function unquote(t, n) {
			if (t[0] === '\'') { if (!t.endsWith('\'') || t.length < 2) { throw yamlError('INPUT-YAML', n, 'Unterminated single-quoted string'); } return t.slice(1, -1).replace(/''/gu, '\''); }
			if (!t.endsWith('"') || t.length < 2) { throw yamlError('INPUT-YAML', n, 'Unterminated double-quoted string'); }
			const body = t.slice(1, -1);
			let o = '';
			for (let k = 0; k < body.length; k++) {
				const c = body[k];
				if (c !== '\\') { o += c; continue; }
				const e = body[++k];
				const m = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', '/': '/', '0': '\u0000', ' ': ' ' };
				if (e === 'x' || e === 'u' || e === 'U') { const len = e === 'x' ? 2 : e === 'u' ? 4 : 8; const h = body.slice(k + 1, k + 1 + len); if (!/^[0-9A-Fa-f]+$/u.test(h) || h.length !== len) { throw yamlError('INPUT-YAML', n, 'Invalid escape in a double-quoted string'); } o += String.fromCodePoint(parseInt(h, 16)); k += len; }
				else if (Object.prototype.hasOwnProperty.call(m, e)) { o += m[e]; } else { throw yamlError('INPUT-YAML', n, 'Invalid escape in a double-quoted string'); }
			}
			return o;
		}
		function scalar(t, n, p) {
			if (/^[&*!]/u.test(t)) { throw yamlError('INPUT-ANCHOR', n, t[0] === '&' ? 'Anchors are not supported' : t[0] === '*' ? 'Aliases are not supported (quote values that start with *)' : 'Tags are not supported'); }
			if (t[0] === '\'' || t[0] === '"') { return unquote(t, n); }
			if (t[0] === '[' || t[0] === '{') { return flow(t, n, p); }
			if (/^(?:null|Null|NULL|~)$/u.test(t)) { return null; }
			if (/^(?:true|True|TRUE)$/u.test(t)) { return true; }
			if (/^(?:false|False|FALSE)$/u.test(t)) { return false; }
			if (/^[-+]?(?:0|[1-9][0-9]*)$/u.test(t) && t.length < 16) { return Number(t); }
			if (/^[-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+)$/u.test(t)) { return Number(t); }
			return t;
		}
		function flow(t, n, p) {
			let k = 0;
			const ws = () => { while (k < t.length && t[k] === ' ') { k++; } };
			function val(depth) {
				if (depth > MAX_DEPTH) { throw yamlError('INPUT-YAML', n, 'Flow collection nested too deeply'); }
				ws();
				const c = t[k];
				if (c === '[') { k++; const a = []; ws(); if (t[k] === ']') { k++; return a; } for (;;) { a.push(val(depth + 1)); ws(); if (t[k] === ',') { k++; ws(); if (t[k] === ']') { k++; return a; } continue; } if (t[k] === ']') { k++; return a; } throw yamlError('INPUT-YAML', n, 'Expected , or ] in a flow list'); } }
				if (c === '{') { k++; const o = {}; ws(); if (t[k] === '}') { k++; return o; } for (;;) { ws(); const key = String(atom(true)); ws(); if (t[k] !== ':') { throw yamlError('INPUT-YAML', n, 'Expected : in a flow mapping'); } k++; if (Object.prototype.hasOwnProperty.call(o, key)) { throw yamlError('INPUT-YAML', n, 'Duplicate key “' + key + '”'); } Object.defineProperty(o, key, { value: val(depth + 1), enumerable: true, writable: true, configurable: true }); ws(); if (t[k] === ',') { k++; continue; } if (t[k] === '}') { k++; return o; } throw yamlError('INPUT-YAML', n, 'Expected , or } in a flow mapping'); } }
				return atom(false);
			}
			function atom(isKey) {
				ws();
				const c = t[k];
				if (c === '\'' || c === '"') { let j = k + 1; for (; j < t.length; j++) { if (t[j] === '\\' && c === '"') { j++; continue; } if (t[j] === c) { if (c === '\'' && t[j + 1] === '\'') { j++; continue; } break; } } const s = unquote(t.slice(k, j + 1), n); k = j + 1; return s; }
				let j = k;
				while (j < t.length && !/[,\]}]/u.test(t[j]) && !(isKey && t[j] === ':')) { j++; }
				const s = t.slice(k, j).trim();
				k = j;
				return isKey ? s : scalar(s, n, p);
			}
			const v = val(0);
			ws();
			if (k < t.length) { throw yamlError('INPUT-YAML', n, 'Unexpected text after a flow collection'); }
			return v;
		}
	}

	// ------------------------------------------------------------------ Dockerfile
	/** Splits a Dockerfile into instructions { op, args, line, text } (continuations joined, heredoc bodies attached). */
	function parseDockerfile(text, tick) {
		const raw = String(text || '').replace(/^\ufeff/u, '').split(/\r\n|\r|\n/u);
		if (raw.length > MAX_LINES) { const e = new Error('The input has more than ' + MAX_LINES + ' lines.'); e.code = 'INPUT-UNKNOWN'; throw e; }
		let esc = '\\';
		for (const l of raw) { const m = /^#\s*escape\s*=\s*([`\\])\s*$/iu.exec(l); if (m) { esc = m[1]; break; } if (!/^#/u.test(l.trim()) || !/^#\s*[a-z]+\s*=/iu.test(l.trim())) { break; } }
		const out = [];
		for (let i = 0; i < raw.length; i++) {
			if (tick && i % 500 === 0) { tick(); }
			const first = raw[i];
			if (!first.trim() || /^\s*#/u.test(first)) { continue; }
			const start = i + 1;
			let text = first;
			while (text.replace(/\s+$/u, '').endsWith(esc) && i + 1 < raw.length) {
				text = text.replace(/\s+$/u, '').slice(0, -1) + ' ';
				i++;
				while (i < raw.length && /^\s*#/u.test(raw[i])) { i++; }
				if (i < raw.length) { text += raw[i]; }
			}
			const m = /^\s*([A-Za-z]+)(?:\s+([\s\S]*))?$/u.exec(text);
			if (!m) { continue; }
			const ins = { op: m[1].toUpperCase(), args: (m[2] || '').trim(), line: start, text: text.trim(), body: '' };
			const hd = [...ins.args.matchAll(/<<-?(["']?)([A-Za-z_][A-Za-z0-9_]*)\1/gu)].map(x => x[2]);
			for (const d of hd) {
				const body = [];
				while (i + 1 < raw.length) { i++; if (raw[i].trim() === d) { break; } body.push(raw[i]); }
				ins.body += body.join('\n') + '\n';
			}
			out.push(ins);
		}
		return out;
	}
	function splitWords(s) {
		const out = [];
		let cur = '', q = '', has = false;
		for (let i = 0; i < s.length; i++) {
			const c = s[i];
			if (q) { if (c === q) { q = ''; } else if (c === '\\' && q === '"' && i + 1 < s.length) { cur += s[++i]; } else { cur += c; } continue; }
			if (c === '"' || c === '\'') { q = c; has = true; continue; }
			if (/\s/u.test(c)) { if (cur || has) { out.push(cur); cur = ''; has = false; } continue; }
			if (c === '\\' && i + 1 < s.length) { cur += s[++i]; has = true; continue; }
			cur += c; has = true;
		}
		if (cur || has) { out.push(cur); }
		return out;
	}
	function envPairs(args, op) {
		const w = splitWords(args);
		if (!w.length) { return []; }
		if (op === 'ARG') { return w.filter(x => !x.startsWith('--')).map(x => { const k = x.indexOf('='); return k < 0 ? [x, ''] : [x.slice(0, k), x.slice(k + 1)]; }); }
		if (!w[0].includes('=')) { return [[w[0], w.slice(1).join(' ')]]; }
		return w.map(x => { const k = x.indexOf('='); return k < 0 ? [x, ''] : [x.slice(0, k), x.slice(k + 1)]; });
	}
	const PIPE_RE = /(?:^|[^\p{L}\p{N}_-])(?:curl|wget)(?:\s[^|;&\n]*)?[|]\s*(?:sudo(?:\s+-[\p{L}]+)*\s+)?(?:env\s+)?(?:[/][^\s]*[/])?(?:sh|bash|zsh|ash|dash|ksh|python[0-9.]*|perl|ruby|node)(?:\s|$|;)/u;
	const SUDO_RE = /(?:^|[\s;&|(])sudo(?:\s|$)/u;
	function auditDockerfile(text, ctx, tick) {
		const ins = parseDockerfile(text, tick);
		if (!ins.some(x => x.op === 'FROM')) { return { error: { code: 'INPUT-UNKNOWN', message: 'No FROM instruction was found, so this is not read as a Dockerfile. ' + INPUT_ERRORS['INPUT-UNKNOWN'], line: 0 } }; }
		const f = [];
		const stages = [];
		let st = null;
		for (const x of ins) {
			if (tick) { tick(); }
			if (x.op === 'FROM') {
				const w = splitWords(x.args).filter(t => !t.startsWith('--'));
				const image = w[0] || '';
				const asI = w.findIndex(t => t.toLowerCase() === 'as');
				const name = asI >= 0 && w[asI + 1] ? w[asI + 1].toLowerCase() : '';
				const parent = stages.find(s => s.name && s.name === image.toLowerCase()) || null;
				st = { name, image, line: x.line, user: parent ? parent.user : null, userLine: parent ? parent.userLine : 0, health: parent ? parent.health : false, index: stages.length + 1 };
				stages.push(st);
				const c = Object.assign({}, ctx, { object: 'stage ' + st.index + (name ? ' (' + name + ')' : '') });
				if (!parent && image.toLowerCase() !== 'scratch') {
					const t = imageTag(image);
					if (t === 'latest') { f.push(finding('DF-TAG-001', c, x.line, 'FROM ' + image)); }
					if (t === 'none') { f.push(finding('DF-TAG-002', c, x.line, 'FROM ' + image)); }
				}
				continue;
			}
			if (!st) { continue; }
			const c = Object.assign({}, ctx, { object: 'stage ' + st.index + (st.name ? ' (' + st.name + ')' : '') });
			if (x.op === 'USER') { st.user = splitWords(x.args)[0] || ''; st.userLine = x.line; }
			else if (x.op === 'HEALTHCHECK') { st.health = true; }
			else if (x.op === 'ENV' || x.op === 'ARG') {
				for (const [k, v] of envPairs(x.args, x.op)) { const ev = secretEvidence(k, v); if (ev) { f.push(finding('DF-SEC-001', c, x.line, x.op + ' ' + ev)); } }
			} else if (x.op === 'ADD') {
				const src = splitWords(x.args).filter(t => !t.startsWith('--')).slice(0, -1);
				if (src.some(s => /^(?:https?|git|ftp):[/][/]/iu.test(s) || /^git@/u.test(s))) { f.push(finding('DF-ADD-001', c, x.line, 'ADD ' + src.join(' '))); }
				else if (src.length) { f.push(finding('DF-HYG-001', c, x.line, 'ADD ' + src.join(' '))); }
			} else if (x.op === 'RUN') {
				const cmd = x.args + (x.body ? '\n' + x.body : '');
				const lines = cmd.split('\n');
				if (lines.some(l => PIPE_RE.test(l))) { f.push(finding('DF-PIPE-001', c, x.line, lines.find(l => PIPE_RE.test(l)).trim().slice(0, 200))); }
				if (SUDO_RE.test(cmd)) { f.push(finding('DF-SUDO-001', c, x.line, 'RUN ' + x.args.slice(0, 160))); }
				if (/apt-get\s+(?:-[^\s]+\s+)*install(?:\s|$)/u.test(cmd) && !cmd.includes('--no-install-recommends')) { f.push(finding('DF-HYG-003', c, x.line, 'RUN ' + x.args.slice(0, 160))); }
				for (const sec of findSecrets(cmd)) { f.push(finding('DF-SEC-001', c, x.line, 'RUN … [' + sec.kind + ': ' + sec.shown + ']')); }
			} else if (x.op === 'EXPOSE') {
				const ports = splitWords(x.args).map(p => parseInt(p, 10)).filter(n => ADMIN_PORTS.has(n));
				if (ports.length) { f.push(finding('DF-PORT-001', c, x.line, 'EXPOSE ' + x.args)); }
			}
		}
		const last = stages[stages.length - 1];
		const lc = Object.assign({}, ctx, { object: 'final stage ' + last.index + (last.name ? ' (' + last.name + ')' : '') });
		if (last.user === null) { f.push(finding('DF-USER-001', lc, last.line, 'FROM ' + last.image)); }
		else if (/^(?:root|0)(?::.*)?$/iu.test(last.user)) { f.push(finding('DF-USER-002', lc, last.userLine, 'USER ' + last.user)); }
		if (!last.health) { f.push(finding('DF-HYG-002', lc, last.line, '')); }
		return { findings: f, documents: 1, objects: stages.length };
	}

	// ------------------------------------------------------------------ Docker Compose
	function lineAt(lines, p) { let q = p; while (q) { if (lines.has(q)) { return lines.get(q); } q = q.slice(0, q.lastIndexOf('/')); } return 0; }
	function auditCompose(doc, di, lines, ctx, tick) {
		const f = [];
		const base = '/doc' + di + '/services';
		for (const [name, svc] of Object.entries(doc.services || {})) {
			if (tick) { tick(); }
			if (!isObj(svc)) { continue; }
			const c = Object.assign({}, ctx, { document: di + 1, object: 'service ' + name });
			const P = k => lineAt(lines, base + '/' + name + (k ? '/' + k : ''));
			const add = (id, k, ev) => f.push(finding(id, c, P(k), ev, { container: name }));
			if (isTrue(svc.privileged)) { add('DC-PRIV-001', 'privileged', 'privileged: true'); }
			const capAdd = arr(svc.cap_add).map(capName).filter(x => DANGEROUS_CAPS.has(x));
			if (capAdd.length) { add('DC-CAP-001', 'cap_add', 'cap_add: ' + capAdd.join(', ')); }
			if (!arr(svc.cap_drop).map(capName).includes('ALL')) { add('DC-CAP-002', svc.cap_drop ? 'cap_drop' : '', ''); }
			const so = arr(svc.security_opt).map(x => String(x).trim().toLowerCase().replace(/=/gu, ':'));
			if (!so.some(x => x === 'no-new-privileges' || x === 'no-new-privileges:true')) { add('DC-ESC-001', svc.security_opt ? 'security_opt' : '', ''); }
			const unconf = so.filter(x => x === 'seccomp:unconfined' || x === 'apparmor:unconfined');
			if (unconf.length) { add('DC-SECO-001', 'security_opt', 'security_opt: ' + unconf.join(', ')); }
			if (!isTrue(svc.read_only)) { add('DC-RO-001', svc.read_only !== undefined ? 'read_only' : '', ''); }
			if (svc.user === undefined || svc.user === null || svc.user === '') { add('DC-USER-002', '', ''); }
			else if (/^(?:root|0)(?::.*)?$/iu.test(String(svc.user).trim())) { add('DC-USER-001', 'user', 'user: ' + svc.user); }
			if (String(svc.network_mode || '').trim() === 'host') { add('DC-HOST-001', 'network_mode', 'network_mode: host'); }
			if (String(svc.pid || '').trim() === 'host') { add('DC-HOST-002', 'pid', 'pid: host'); }
			if (String(svc.ipc || '').trim() === 'host') { add('DC-HOST-003', 'ipc', 'ipc: host'); }
			arr(svc.volumes).forEach((v, i) => {
				let src = '';
				if (typeof v === 'string') { src = v.split(':')[0]; } else if (isObj(v) && (v.type === 'bind' || v.type === undefined)) { src = String(v.source || ''); }
				const cls = hostPathClass(src);
				if (cls === 'socket') { add('DC-SOCK-001', 'volumes/' + i, 'volume ' + src); } else if (cls === 'sensitive') { add('DC-PATH-001', 'volumes/' + i, 'volume ' + src); }
			});
			if (svc.image !== undefined) { const t = imageTag(svc.image); if (t === 'latest') { add('DC-TAG-001', 'image', 'image: ' + svc.image); } if (t === 'none') { add('DC-TAG-002', 'image', 'image: ' + svc.image); } }
			const env = svc.environment;
			if (isObj(env)) { for (const [k, v] of Object.entries(env)) { const ev = secretEvidence(k, v); if (ev) { add('DC-SEC-001', 'environment/' + k, ev); } } }
			else { arr(env).forEach((e, i) => { const s = String(e); const k = s.indexOf('='); if (k > 0) { const ev = secretEvidence(s.slice(0, k), s.slice(k + 1)); if (ev) { add('DC-SEC-001', 'environment/' + i, ev); } } }); }
			const lim = isObj(svc.deploy) && isObj(svc.deploy.resources) && isObj(svc.deploy.resources.limits) ? svc.deploy.resources.limits : {};
			const mem = svc.mem_limit !== undefined || lim.memory !== undefined;
			const cpu = svc.cpus !== undefined || svc.cpu_quota !== undefined || lim.cpus !== undefined;
			if (!mem || !cpu) { add('DC-RES-001', '', !mem && !cpu ? 'no memory and no CPU limit' : !mem ? 'no memory limit' : 'no CPU limit'); }
			let admin = '', open = '';
			arr(svc.ports).forEach(p => {
				let hostIp = '', published = '', target = '';
				if (isObj(p)) { hostIp = String(p.host_ip || ''); published = String(p.published || ''); target = String(p.target || ''); }
				else {
					let s = String(p).trim().replace(/[/](?:tcp|udp|sctp)$/iu, '');
					const v6 = /^\[([^\]]+)\]:(.*)$/u.exec(s);
					if (v6) { hostIp = v6[1]; s = v6[2]; }
					const parts = s.split(':');
					if (parts.length >= 3) { hostIp = hostIp || parts.slice(0, parts.length - 2).join(':'); published = parts[parts.length - 2]; target = parts[parts.length - 1]; }
					else if (parts.length === 2) { published = parts[0]; target = parts[1]; }
					else { target = parts[0]; }
				}
				const tp = parseInt(target.split('-')[0], 10);
				if (ADMIN_PORTS.has(tp) && !admin) { admin = String(isObj(p) ? target : p); }
				if (!hostIp || hostIp === '0.0.0.0' || hostIp === '::') { if (!open) { open = String(isObj(p) ? (published || target) : p); } }
			});
			if (admin) { add('DC-PORT-001', 'ports', 'ports: ' + admin); }
			if (open) { add('DC-HYG-001', 'ports', 'ports: ' + open); }
			if (svc.healthcheck === undefined) { add('DC-HYG-002', '', ''); }
		}
		return f;
	}

	// ------------------------------------------------------------------ Kubernetes
	const POD_PATHS = { Pod: ['spec'], Deployment: ['spec', 'template', 'spec'], StatefulSet: ['spec', 'template', 'spec'], DaemonSet: ['spec', 'template', 'spec'], ReplicaSet: ['spec', 'template', 'spec'], ReplicationController: ['spec', 'template', 'spec'], Job: ['spec', 'template', 'spec'], CronJob: ['spec', 'jobTemplate', 'spec', 'template', 'spec'] };
	const get = (o, path) => path.reduce((v, k) => (isObj(v) || Array.isArray(v) ? v[k] : undefined), o);
	const okProfile = t => t === 'RuntimeDefault' || t === 'Localhost';
	function auditK8sObject(obj, P, ctx, saNoMount, f, tick) {
		if (tick) { tick(); }
		const kind = String(obj.kind || '');
		const name = String(get(obj, ['metadata', 'name']) || '');
		const c0 = Object.assign({}, ctx, { object: kind + (name ? ' ' + name : '') });
		const add = (id, path, ev, container) => f.push(finding(id, c0, P(path), ev, { container: container || '' }));
		if (kind === 'Role' || kind === 'ClusterRole') {
			arr(obj.rules).forEach((r, i) => { if (!isObj(r)) { return; } const wild = ['apiGroups', 'resources', 'verbs'].filter(k => arr(r[k]).map(String).includes('*')); if (wild.length) { add('K8S-RBAC-001', ['rules', i], 'rule ' + (i + 1) + ': * in ' + wild.join(', ')); } });
			return;
		}
		if (kind === 'RoleBinding' || kind === 'ClusterRoleBinding') { if (String(get(obj, ['roleRef', 'name']) || '') === 'cluster-admin') { add('K8S-RBAC-002', ['roleRef', 'name'], 'roleRef: cluster-admin'); } return; }
		if (kind === 'Secret') {
			const vals = [];
			for (const k of ['data', 'stringData']) { if (isObj(obj[k])) { for (const [n, v] of Object.entries(obj[k])) { if (v !== null && String(v) !== '') { vals.push(n + ' = ' + hideAll(v)); } } } }
			if (vals.length) { add('K8S-SEC-002', [isObj(obj.stringData) ? 'stringData' : 'data'], vals.slice(0, 5).join('; ')); }
			return;
		}
		if (kind === 'ConfigMap') { if (isObj(obj.data)) { for (const [n, v] of Object.entries(obj.data)) { const ev = secretEvidence(n, v); if (ev) { add('K8S-SEC-001', ['data', n], ev); } } } return; }
		const pp = POD_PATHS[kind];
		if (!pp) { return; }
		const spec = get(obj, pp);
		if (!isObj(spec)) { return; }
		const meta = get(obj, pp.slice(0, -1).concat(['metadata'])) || {};
		const ann = isObj(meta.annotations) ? meta.annotations : {};
		const longRunning = kind !== 'Job' && kind !== 'CronJob';
		const S = rest => pp.concat(rest);
		const psc = isObj(spec.securityContext) ? spec.securityContext : {};
		if (isTrue(spec.hostNetwork)) { add('K8S-HOST-001', S(['hostNetwork']), 'hostNetwork: true'); }
		if (isTrue(spec.hostPID)) { add('K8S-HOST-002', S(['hostPID']), 'hostPID: true'); }
		if (isTrue(spec.hostIPC)) { add('K8S-HOST-003', S(['hostIPC']), 'hostIPC: true'); }
		arr(spec.volumes).forEach((v, i) => {
			if (!isObj(v) || !isObj(v.hostPath)) { return; }
			const cls = hostPathClass(v.hostPath.path);
			const id = cls === 'socket' ? 'K8S-SOCK-001' : cls === 'sensitive' ? 'K8S-PATH-001' : 'K8S-PATH-002';
			add(id, S(['volumes', i, 'hostPath', 'path']), 'hostPath: ' + v.hostPath.path + (v.name ? ' (volume ' + v.name + ')' : ''));
		});
		const saName = String(spec.serviceAccountName || spec.serviceAccount || '');
		if (!saName || saName === 'default') { add('K8S-SA-001', S(saName ? ['serviceAccountName'] : []), saName ? 'serviceAccountName: default' : 'serviceAccountName not set'); }
		if (spec.automountServiceAccountToken !== false && !saNoMount.has(saName || 'default')) { add('K8S-SA-002', S(spec.automountServiceAccountToken !== undefined ? ['automountServiceAccountToken'] : []), spec.automountServiceAccountToken !== undefined ? 'automountServiceAccountToken: ' + spec.automountServiceAccountToken : 'automountServiceAccountToken not set'); }
		const all = arr(spec.initContainers).map((x, i) => ({ c: x, init: true, path: ['initContainers', i] })).concat(arr(spec.containers).map((x, i) => ({ c: x, init: false, path: ['containers', i] }))).filter(x => isObj(x.c));
		// seccomp and AppArmor: pod level, else every container
		const podSec = get(psc, ['seccompProfile', 'type']);
		const annSec = String(ann['seccomp.security.alpha.kubernetes.io/pod'] || '');
		const conSec = all.map(x => get(x.c, ['securityContext', 'seccompProfile', 'type']));
		if (podSec === 'Unconfined' || conSec.includes('Unconfined') || annSec === 'unconfined') { add('K8S-SECCOMP-002', S(['securityContext', 'seccompProfile', 'type']), 'seccompProfile: Unconfined'); }
		else if (!okProfile(podSec) && !/^(?:runtime[/]default|docker[/]default|localhost[/])/u.test(annSec) && !(all.length && conSec.every(okProfile))) { add('K8S-SECCOMP-001', S(['securityContext']), 'no seccompProfile'); }
		const podAa = get(psc, ['appArmorProfile', 'type']);
		const aaOf = x => { const t = get(x.c, ['securityContext', 'appArmorProfile', 'type']); if (t) { return t; } const a = String(ann['container.apparmor.security.beta.kubernetes.io/' + x.c.name] || ''); return a === 'runtime/default' ? 'RuntimeDefault' : a.startsWith('localhost/') ? 'Localhost' : a === 'unconfined' ? 'Unconfined' : ''; };
		const conAa = all.map(aaOf);
		if (podAa === 'Unconfined' || conAa.includes('Unconfined')) { add('K8S-APPARMOR-002', S(['securityContext', 'appArmorProfile', 'type']), 'appArmorProfile: Unconfined'); }
		else if (!okProfile(podAa) && !(all.length && conAa.every(okProfile))) { add('K8S-APPARMOR-001', S(['securityContext']), 'no AppArmor profile'); }
		for (const x of all) {
			const cn = String(x.c.name || '');
			const sc = isObj(x.c.securityContext) ? x.c.securityContext : {};
			const C = rest => S(x.path.concat(rest));
			const addC = (id, rest, ev) => add(id, C(rest), ev, cn);
			if (isTrue(sc.privileged)) { addC('K8S-PRIV-001', ['securityContext', 'privileged'], 'privileged: true'); }
			if (sc.allowPrivilegeEscalation !== false) { addC('K8S-ESC-001', sc.allowPrivilegeEscalation !== undefined ? ['securityContext', 'allowPrivilegeEscalation'] : ['name'], 'allowPrivilegeEscalation: ' + (sc.allowPrivilegeEscalation === undefined ? 'not set' : sc.allowPrivilegeEscalation)); }
			const caps = isObj(sc.capabilities) ? sc.capabilities : {};
			const bad = arr(caps.add).map(capName).filter(v => DANGEROUS_CAPS.has(v));
			if (bad.length) { addC('K8S-CAP-001', ['securityContext', 'capabilities', 'add'], 'capabilities.add: ' + bad.join(', ')); }
			if (!arr(caps.drop).map(capName).includes('ALL')) { addC('K8S-CAP-002', ['name'], 'capabilities.drop: ' + (arr(caps.drop).join(', ') || 'not set')); }
			if (sc.readOnlyRootFilesystem !== true) { addC('K8S-RO-001', sc.readOnlyRootFilesystem !== undefined ? ['securityContext', 'readOnlyRootFilesystem'] : ['name'], 'readOnlyRootFilesystem: ' + (sc.readOnlyRootFilesystem === undefined ? 'not set' : sc.readOnlyRootFilesystem)); }
			const uid = sc.runAsUser !== undefined ? sc.runAsUser : psc.runAsUser;
			const nonRoot = sc.runAsNonRoot !== undefined ? sc.runAsNonRoot : psc.runAsNonRoot;
			if (uid === 0 || uid === '0') { addC('K8S-USER-001', sc.runAsUser !== undefined ? ['securityContext', 'runAsUser'] : ['name'], 'runAsUser: 0' + (sc.runAsUser === undefined ? ' (pod)' : '')); }
			else if (nonRoot !== true && !(Number(uid) > 0)) { addC('K8S-USER-002', ['name'], 'runAsNonRoot not set'); }
			if (x.c.image !== undefined) { const t = imageTag(x.c.image); if (t === 'latest') { addC('K8S-TAG-001', ['image'], 'image: ' + x.c.image); } if (t === 'none') { addC('K8S-TAG-002', ['image'], 'image: ' + x.c.image); } }
			arr(x.c.env).forEach((e, i) => { if (!isObj(e) || e.value === undefined) { return; } const v = String(e.value); if (/^[$][(]/u.test(v)) { return; } const ev = secretEvidence(e.name, v); if (ev) { addC('K8S-SEC-001', ['env', i], ev); } });
			if (arr(x.c.ports).some(p => isObj(p) && p.hostPort !== undefined)) { const i = arr(x.c.ports).findIndex(p => isObj(p) && p.hostPort !== undefined); addC('K8S-PORT-001', ['ports', i, 'hostPort'], 'hostPort: ' + x.c.ports[i].hostPort); }
			const lim = get(x.c, ['resources', 'limits']) || {};
			if (!isObj(lim) || lim.memory === undefined || lim.cpu === undefined) { addC('K8S-RES-001', ['name'], !isObj(lim) || (lim.memory === undefined && lim.cpu === undefined) ? 'no memory and no CPU limit' : lim.memory === undefined ? 'no memory limit' : 'no CPU limit'); }
			if (!x.init && longRunning) {
				if (!isObj(x.c.livenessProbe)) { addC('K8S-PROBE-001', ['name'], ''); }
				if (!isObj(x.c.readinessProbe)) { addC('K8S-PROBE-002', ['name'], ''); }
			}
		}
	}
	function auditKubernetes(docs, lines, ctx, tick) {
		const f = [];
		const saNoMount = new Set();
		const objects = [];
		docs.forEach((d, di) => {
			const v = d.value;
			if (!isObj(v)) { return; }
			if (v.kind === 'List' && Array.isArray(v.items)) { v.items.forEach((it, ii) => { if (isObj(it)) { objects.push({ obj: it, di, base: ['items', ii] }); } }); }
			else if (typeof v.kind === 'string') { objects.push({ obj: v, di, base: [] }); }
		});
		for (const o of objects) { if (o.obj.kind === 'ServiceAccount' && o.obj.automountServiceAccountToken === false) { saNoMount.add(String(get(o.obj, ['metadata', 'name']) || '')); } }
		for (const o of objects) {
			const P = path => lineAt(lines, '/doc' + o.di + (o.base.concat(path).length ? '/' + o.base.concat(path).join('/') : '')) || docs[o.di].line;
			auditK8sObject(o.obj, P, Object.assign({}, ctx, { document: o.di + 1 }), saNoMount, f, tick);
		}
		return { findings: f, objects: objects.length };
	}

	// ------------------------------------------------------------------ entry points
	const KINDS = { dockerfile: 'Dockerfile', compose: 'Docker Compose', kubernetes: 'Kubernetes YAML' };
	function looksLikeDockerfile(text, name) {
		if (/(?:^|[/\\])(?:Dockerfile|Containerfile)(?:[.][^/\\]*)?$|[.](?:dockerfile|containerfile)$/iu.test(String(name || ''))) { return true; }
		const first = String(text).split(/\r\n|\r|\n/u).find(l => l.trim() && !/^\s*#/u.test(l)) || '';
		return /^\s*(?:FROM|ARG)\s+[^\s:]/iu.test(first) && /^\s*FROM\s+\S/imu.test(text);
	}
	/** audit(text, { name, kind: 'auto'|'dockerfile'|'compose'|'kubernetes' }) -> per-file result; never throws for content problems. */
	/** Masks every user-derived string of a file result (Codex acceptance SEC-06): file, object and container names,
	 * evidence and error messages. Applied once when a result leaves audit()/auditFiles() and again in exportReport(). */
	function maskResult(res) {
		const M = v => (typeof v === 'string' ? maskSecrets(v) : v);
		return Object.assign({}, res, { file: M(res.file), error: res.error ? Object.assign({}, res.error, { message: M(res.error.message) }) : res.error, findings: (res.findings || []).map(x => Object.assign({}, x, { file: M(x.file), object: M(x.object), container: M(x.container), evidence: M(x.evidence) })) });
	}
	function audit(text, opts) {
		return maskResult(auditRaw(text, opts));
	}
	function auditRaw(text, opts) {
		const o = opts || {};
		const s = String(text === undefined || text === null ? '' : text);
		if (s.length > MAX_INPUT_CHARS) { const e = new Error('The file is larger than 1 MB.'); e.code = 'TOO_LARGE'; throw e; }
		if (!s.trim()) { const e = new Error('The input is empty.'); e.code = 'EMPTY'; throw e; }
		const tick = o.tick || budget();
		const file = nfc(String(o.name || 'pasted input')).slice(0, 200);
		const ctx = { file, document: 0, object: '' };
		const res = { engine: ENGINE, ruleset: RULESET, file, kind: '', kindLabel: '', documents: 0, objects: 0, findings: [], counts: { high: 0, medium: 0, low: 0, info: 0 }, error: null };
		const fail = (code, message, line) => { res.error = { code, message: message || INPUT_ERRORS[code], line: line || 0 }; return res; };
		const want = ['dockerfile', 'compose', 'kubernetes'].includes(o.kind) ? o.kind : 'auto';
		if (want === 'dockerfile' || (want === 'auto' && looksLikeDockerfile(s, o.name))) {
			res.kind = 'dockerfile';
			const r = auditDockerfile(s, ctx, tick);
			if (r.error) { return fail(r.error.code, r.error.message); }
			res.findings = r.findings; res.documents = r.documents; res.objects = r.objects;
		} else {
			if (/\{\{[\s\S]*?\}\}/u.test(s)) { res.kind = 'helm'; const ln = s.slice(0, s.indexOf('{{')).split('\n').length; return fail('INPUT-HELM', '', ln); }
			if (!/^\s*(?:-\s+)?["']?[\p{L}\p{N}_.\-/]+["']?\s*:(?:\s|$)/mu.test(s)) { return fail('INPUT-UNKNOWN'); }
			let y;
			try { y = parseYaml(s, tick); } catch (e) { if (e.code === 'INPUT-ANCHOR') { return fail('INPUT-ANCHOR', INPUT_ERRORS['INPUT-ANCHOR'] + ' ' + e.message + '.', e.line); } if (e.code === 'INPUT-YAML') { return fail('INPUT-YAML', 'The YAML could not be read: ' + e.message + '.', e.line); } throw e; }
			res.documents = y.docs.length;
			const isCompose = d => isObj(d.value) && isObj(d.value.services) && d.value.apiVersion === undefined;
			const isK8s = d => isObj(d.value) && typeof d.value.kind === 'string' && typeof d.value.apiVersion === 'string';
			if ((want === 'compose' || want === 'auto') && y.docs.some(isCompose)) {
				res.kind = 'compose';
				y.docs.forEach((d, di) => { if (isCompose(d)) { const r = auditCompose(d.value, di, y.lines, ctx, tick); res.findings.push(...r); res.objects += Object.keys(d.value.services).length; } });
			} else if ((want === 'kubernetes' || want === 'auto') && y.docs.some(isK8s)) {
				res.kind = 'kubernetes';
				const r = auditKubernetes(y.docs, y.lines, ctx, tick);
				res.findings = r.findings; res.objects = r.objects;
			} else { return fail('INPUT-UNKNOWN', want === 'auto' ? '' : 'No ' + KINDS[want] + ' content was found (' + (want === 'compose' ? 'a top-level services: mapping' : 'objects with apiVersion and kind') + ' expected).'); }
		}
		res.kindLabel = KINDS[res.kind];
		res.findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.document - b.document || a.line - b.line || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
		for (const x of res.findings) { res.counts[x.severity]++; }
		return res;
	}
	/** auditFiles([{ name, text, kind }]) -> { files: [result], counts } */
	function auditFiles(files, opts) {
		const list = arr(files);
		if (!list.length) { const e = new Error('Add a Dockerfile, Compose file or Kubernetes manifest first.'); e.code = 'EMPTY'; throw e; }
		if (list.length > MAX_FILES) { const e = new Error('At most ' + MAX_FILES + ' files can be checked at once.'); e.code = 'TOO_MANY'; throw e; }
		if (list.reduce((n, x) => n + String(x.text || '').length, 0) > MAX_TOTAL_CHARS) { const e = new Error('The files together are larger than 4 MB.'); e.code = 'TOO_LARGE'; throw e; }
		const tick = budget();
		const out = [];
		list.forEach((x, i) => {
			const o = Object.assign({}, opts || {}, { name: x.name || (list.length > 1 ? 'input ' + (i + 1) : 'pasted input'), kind: x.kind, tick });
			try { out.push(audit(x.text, o)); } catch (e) { if (e.code === 'TIMEOUT') { throw e; } out.push({ engine: ENGINE, ruleset: RULESET, file: nfc(String(o.name)).slice(0, 200), kind: '', kindLabel: '', documents: 0, objects: 0, findings: [], counts: { high: 0, medium: 0, low: 0, info: 0 }, error: { code: e.code || 'FAILED', message: maskSecrets(e.message), line: 0 } }); out[out.length - 1].file = maskSecrets(out[out.length - 1].file); }
		});
		const counts = { high: 0, medium: 0, low: 0, info: 0 };
		for (const r of out) { for (const k of Object.keys(counts)) { counts[k] += r.counts[k]; } }
		return { engine: ENGINE, ruleset: RULESET, files: out, counts };
	}

	const NOTE = 'Static checks of the text only. This checklist is a starting point, not a complete audit: no findings does not mean a configuration is safe, and runtime settings, admission policies, images and the cluster itself were not checked. Nothing was changed; review each item before you edit your files. Secrets found in files are masked.';
	const mdEsc = s => String(s).replace(/([\\`*_{}[\]<>()#+!|~])/gu, '\\$1').replace(/\r?\n/gu, ' ');
	function where(f) { return [f.line ? 'line ' + f.line : '', f.document ? 'document ' + f.document : '', f.object, f.container && !f.object.endsWith(' ' + f.container) ? 'container ' + f.container : ''].filter(Boolean).join(' · '); }
	function exportReport(result, opts) {
		const o = opts || {};
		result = Object.assign({}, result, { files: result.files.map(maskResult) });
		const json = { tool: 'CyberDat Docker & Kubernetes Hardening Audit Generator', engine: ENGINE, ruleset: RULESET, generatedAt: o.timestamp || new Date().toISOString(), note: NOTE, counts: result.counts, files: result.files.map(r => ({ file: r.file, kind: r.kindLabel || null, documents: r.documents, objects: r.objects, error: r.error, counts: r.counts, findings: r.findings })) };
		const L = ['# Container hardening checklist', '', 'Generated with CyberDat Docker & Kubernetes Hardening Audit Generator ' + ENGINE + ' (rules ' + RULESET + ') on ' + mdEsc(json.generatedAt) + '.', '', '> ' + NOTE, '', '- High: ' + result.counts.high + '; medium: ' + result.counts.medium + '; low: ' + result.counts.low + '; hygiene (info): ' + result.counts.info, ''];
		for (const r of result.files) {
			L.push('## ' + mdEsc(r.file) + (r.kindLabel ? ' (' + r.kindLabel + ')' : ''), '');
			if (r.error) { L.push('Not checked: ' + mdEsc(r.error.message), ''); continue; }
			if (!r.findings.length) { L.push('No findings from these checks. This does not mean the configuration is safe.', ''); continue; }
			const sec = r.findings.filter(f => f.group === 'security'), hyg = r.findings.filter(f => f.group === 'hygiene');
			const item = f => { L.push('- [ ] **' + f.severity.toUpperCase() + '** ' + f.id + ' — ' + mdEsc(f.title) + (where(f) ? ' (' + mdEsc(where(f)) + ')' : '')); if (f.evidence) { L.push('  - Found: `' + f.evidence.replace(/`/gu, '\'') + '`'); } L.push('  - Why: ' + mdEsc(f.explanation), '  - Suggested change: ' + mdEsc(f.fix)); };
			if (sec.length) { L.push('### Security findings', ''); sec.forEach(item); L.push(''); }
			if (hyg.length) { L.push('### Hygiene (info)', ''); hyg.forEach(item); L.push(''); }
		}
		return { json: JSON.stringify(json, null, 2) + '\n', markdown: L.join('\n') + '\n' };
	}

	const EXAMPLE_DOCKERFILE = '# Example Dockerfile written by CyberDat (contains deliberate problems)\nFROM node:latest\nWORKDIR /app\nRUN apt-get update && apt-get install -y curl\nRUN curl -fsSL https://get.example.com/setup.sh | bash\nCOPY package.json server.js ./\nRUN npm ci --omit=dev\nENV NODE_ENV=production\nEXPOSE 3000\nCMD ["node", "server.js"]\n';
	const EXAMPLE_COMPOSE = '# Example Compose file written by CyberDat (contains deliberate problems)\nservices:\n  web:\n    image: nginx:1.27.2\n    read_only: true\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    user: "101:101"\n    mem_limit: 256m\n    cpus: 0.5\n    ports:\n      - "127.0.0.1:8080:8080"\n    healthcheck:\n      test: ["CMD", "wget", "-q", "-O-", "http://localhost:8080/"]\n  agent:\n    image: monitoring.example.com/agent\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n    environment:\n      AGENT_PASSWORD: example-only-change-me\n';
	const EXAMPLE_KUBERNETES = '# Example manifests written by CyberDat (contain deliberate problems)\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: shop\nspec:\n  replicas: 2\n  selector:\n    matchLabels:\n      app: shop\n  template:\n    metadata:\n      labels:\n        app: shop\n    spec:\n      containers:\n        - name: shop\n          image: registry.example.com/shop:2.3.1\n          ports:\n            - containerPort: 8080\n          resources:\n            limits:\n              memory: 256Mi\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: shop-admin\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n  - kind: ServiceAccount\n    name: default\n    namespace: shop\n';

	return { ENGINE, RULESET, MAX_INPUT_CHARS, MAX_TOTAL_CHARS, MAX_FILES, DEF, INPUT_ERRORS, KINDS, parseYaml, parseDockerfile, audit, auditFiles, exportReport, findSecrets, maskSecrets, imageTag, EXAMPLE_DOCKERFILE, EXAMPLE_COMPOSE, EXAMPLE_KUBERNETES };
}));
