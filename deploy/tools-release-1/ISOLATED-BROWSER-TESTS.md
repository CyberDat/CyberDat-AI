# Isolated browser verification — Debian13, no system installation

Test-only runtime outside the repository/theme: Node22.14.0, Playwright1.56.1,
Chromium141.0.7390.37 (build1194), Firefox142.0.1 (1495), WebKit26.0 (2215).
Playwright1.55 added Debian13 support; the prior1.49.1 chose Ubuntu20.04 fallback
with incompatible legacy dependencies. [Official release notes](https://playwright.dev/docs/release-notes#version-155).
No browser/node/npm dependency is shipped with the theme.

The runtime lives under /home/cyberdat/cyberdat-deploy/tools-release-test-runtime/.
Download/install npm dependencies with a private --prefix/--cache and
--ignore-scripts; browser downloads use a private PLAYWRIGHT_BROWSERS_PATH.
Use apt-get download and dpkg-deb -x to obtain missing official Debian libraries
in a private directory. NEVER apt install/update, ldconfig, edit /etc, create a
service or expose a test listener beyond127.0.0.1. The recorded52 package names,
versions and SHA256 values are in stabilization-evidence/webkit-private-dependencies.json.
Package-state/source-config SHA fingerprints before and after must remain equal.

WebKit's bundled MiniBrowser wrapper overwrites LD_LIBRARY_PATH. A task-local
CYBERDAT_WEBKIT_EXECUTABLE loader sets the same WEBKIT_EXEC_PATH,
WEBKIT_INJECTED_BUNDLE_PATH, WEBKIT_INSPECTOR_RESOURCES_PATH and
WEBKIT_FORCE_COMPLEX_TEXT, with bundled AND private library directories. It launches
the original, unchanged bundled bin/MiniBrowser. This avoids reliance on the
Playwright global ldconfig-cache heuristic while the actual dynamic loader still
must resolve every library. No global cache or browser TLS/security policy changes.

EGL also needs the privately extracted Mesa vendor JSON and software driver:
LIBGL_ALWAYS_SOFTWARE=1, GALLIUM_DRIVER=llvmpipe, EGL_PLATFORM=surfaceless,
__EGL_VENDOR_LIBRARY_FILENAMES=<private>/usr/share/glvnd/egl_vendor.d/50_mesa.json,
LIBGL_DRIVERS_PATH=<private>/usr/lib/x86_64-linux-gnu/dri. Without these, WebKit's
page process aborts with “Could not create WPE EGL display”. Normal browser tests
use software rendering; no GPU benchmark is run. Exact loader source is retained
in stabilization-evidence/isolated-browser-runtime.json. A diagnostic native
WebKit automation warning is retained in the launch log; page creation/navigation
and the real suite determine success, not just process startup.

Run tests/tools-sandbox-server.py --port 18091 in the isolated source checkout;
it renders pure PHP doubles and static files, not WordPress/plugins/SQL. Tests
receive explicit http://127.0.0.1:18091/tools/<slug>/ URLs and private evidence paths.
Set NODE_PATH=<private Playwright node_modules>, PLAYWRIGHT_BROWSERS_PATH,
LD_LIBRARY_PATH and CYBERDAT_WEBKIT_EXECUTABLE. CDP Chromium suites use the existing
CYBERDAT_BROWSER private launcher; --no-sandbox applies only to these synthetic
loopback tests in the restricted runtime, not to site/server configuration.

Run each original four-tool *-browser.test.cjs for Chromium and each
*-xbrowser.test.cjs with firefox and webkit arguments sequentially. No SKIP is a
PASS. Bound each test controller and clean up only its own process group. Performance
Node tests are serialized separately from browser workloads; original4000ms
thresholds and all signatures remain unchanged. WebKit is an engine test, not
physical Safari/iOS device acceptance. Screenshots show the local fixture, not staging.
