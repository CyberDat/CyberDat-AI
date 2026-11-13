"""Proposed catalogue 404 check: behavioural test without network access.

The staging scripts verify that unfinished tool URLs return 404. With released tools, only catalogue entries whose
status is not "available" may be required to return 404. This test extracts the catalogue loop from each script's
main() with ast, runs it against stub HTTP functions and checks which URLs are probed.
    python -B tests/catalog-404-check.test.py
"""
import ast
import json
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = ['deploy/research/resume-research.py', 'deploy/research/update-research.py', 'deploy/staging/update-tools-ui.py']
CATALOG = json.loads((ROOT / 'wp-content/themes/cyberdat/inc/tools-catalog.json').read_text(encoding='utf-8'))


def catalogue_loop(path):
    tree = ast.parse((ROOT / path).read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.For) and 'tools-catalog.json' in ast.unparse(node.iter):
            return node
    raise AssertionError(path + ': catalogue loop not found')


def probed(path, catalog, status_for):
    loop = catalogue_loop(path)
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        (base / 'theme/inc').mkdir(parents=True)
        (base / 'theme/inc/tools-catalog.json').write_text(json.dumps(catalog), encoding='utf-8')
        calls = []

        def http(url, *args, **kwargs):
            calls.append(url)
            return (status_for(url), {}, b'')

        def need(ok, message):
            if not ok:
                raise RuntimeError(message)

        scope = {'json': json, 'B': base, 'fetch': http, 'get': http, 'basic': None, 'password': None, 'need': need}
        exec(compile(ast.Module(body=[loop], type_ignores=[]), path, 'exec'), scope)
        return calls


def main():
    available = {t['url'] for t in CATALOG if t.get('status') == 'available'}
    planned = {t['url'] for t in CATALOG if t.get('status') != 'available'}
    assert available == {'/tools/log-anonymizer/', '/tools/prompt-injection-detector/', '/tools/lotl-command-analyzer/', '/tools/mcp-security-checker/'}, available
    assert len(planned) == 6
    for path in SCRIPTS:
        # Published tools return 200: the check must pass and probe only planned tools.
        calls = probed(path, CATALOG, lambda url: 200 if url in available else 404)
        assert set(calls) == planned, (path, calls)
        print('PASS: ' + path + ': the four available tools are skipped, the six planned URLs must stay 404')
        # A planned tool that suddenly answers 200 must still fail the check.
        leaked = sorted(planned)[0]
        try:
            probed(path, CATALOG, lambda url: 200 if url in available or url == leaked else 404)
        except RuntimeError:
            print('PASS: ' + path + ': a planned tool answering 200 still fails')
        else:
            raise AssertionError(path + ': planned tool route change not detected')
        # Without status fields (old catalogue) every URL is still required to be 404.
        old = [{k: v for k, v in t.items() if k != 'status'} for t in CATALOG]
        assert len(probed(path, old, lambda url: 404)) == 10
        print('PASS: ' + path + ': entries without status keep the original strict 404 check')
    print('All catalogue 404 check tests passed.')


if __name__ == '__main__':
    main()
