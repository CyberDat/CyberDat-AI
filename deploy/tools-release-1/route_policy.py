"""One route policy for all future release checks. No old bundled catalogues."""
from safe_theme import need

TOOLS = {
    'log-anonymizer': ('cyberdat_log_anonymizer_render', 'data-log-anonymizer'),
    'prompt-injection-detector': ('cyberdat_prompt_detector_render', 'data-prompt-detector'),
    'lotl-command-analyzer': ('cyberdat_lotl_render', 'data-lotl-analyzer'),
    'mcp-security-checker': ('cyberdat_mcp_render', 'data-mcp-checker'),
}
OLD_PLANNED = ['iot-exposure-query-builder', 'lolbas-analyzer', 'modbus-decoder', 'webhook-oob-listener']


def validate(catalogue, state, fetch):
    available = {x['slug'] for x in catalogue if x.get('status') == 'available'}
    need(available == set(TOOLS), 'catalogue available set differs from pinned release')
    planned = {x['slug'] for x in catalogue if x.get('status') != 'available'} | set(OLD_PLANNED)
    need(len({x['slug'] for x in catalogue}) == len(catalogue), 'duplicate catalogue slug')
    results = {}
    for slug in sorted(available | planned):
        path = '/tools/' + slug + '/'
        status, body = fetch(path)
        page = state.get(slug, {})
        if slug in available and page.get('published'):
            renderer, marker = TOOLS[slug]
            need(page.get('ready') is True and page.get('renderer') == renderer,
                 'published tool renderer/readiness mismatch: ' + slug)
            need(status == 200 and marker.encode() in body, 'published tool HTTP/HTML mismatch: ' + slug)
        else:
            need(not page.get('published') and status == 404, 'planned/unpublished tool must stay 404: ' + slug)
        results[path] = status
    return results
