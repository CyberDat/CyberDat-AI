"""Exercise browser interception without opening a browser/socket or reading credentials."""
import importlib.util,pathlib,sys
sys.dont_write_bytecode=True
p=pathlib.Path(__file__).resolve().parents[1]/'deploy/analytics-2.1/capture-analytics.py';spec=importlib.util.spec_from_file_location('capture_under_test',p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
client=module.DevTools.__new__(module.DevTools);client.id=0;client.authorization='TEST-ONLY-NOT-A-CREDENTIAL';messages=[];client.send=messages.append
client.event({'method':'Fetch.requestPaused','params':{'requestId':'fixture','request':{'url':'https://staging.cyberdat.eu/wp-json/cyberdat-analytics/v1/records?group=overlap&value=kev_only&days=30&q=CVE-2026-12345','headers':{'Authorization':'REPLACED-TEST-VALUE'}}}})
assert client.analytics_filter=={'group':'overlap','value':'kev_only','date':'','days':'30'}
assert 'q' not in client.analytics_filter and 'Authorization' not in client.analytics_filter
assert messages[-1]['method']=='Fetch.continueRequest'
headers=messages[-1]['params']['headers'];assert len([h for h in headers if h['name'].lower()=='authorization'])==1
client.event({'method':'Fetch.requestPaused','params':{'requestId':'external','request':{'url':'https://example.invalid/wp-json/cyberdat-analytics/v1/records?group=severity&value=High','headers':{}}}})
assert messages[-1]['method']=='Fetch.failRequest' and 'headers' not in messages[-1]['params']
assert client.analytics_filter['value']=='kev_only'
print('PASS: actual request-filter evidence; credentials excluded from diagnostics; external requests remain blocked; no browser/network used')
assert module.debugging_port('49152\n/devtools/browser/test-123\n')==49152
for text in ['0\n/devtools/browser/test','65536\n/devtools/browser/test','9222\nhttps://example.invalid/','bad\n/devtools/browser/test','9222']:
 try:module.debugging_port(text)
 except RuntimeError:pass
 else:raise AssertionError('Invalid port file accepted')
source=p.read_text();assert source.index('cdp=DevTools(')<source.index('password=read_basic_password(')
assert '--remote-debugging-port=0' in source and 'winreg.KEY_READ' in source and 'SetValue' not in source
print('PASS: ephemeral port validation, startup before credentials, read-only Edge policy inspection')
import html
valid={'periods':{'7':{},'30':{},'90':{}}}
parser=module.HomeState();parser.feed('<section data-threat-pulse="2.1" data-pulse-periods="'+html.escape(__import__('json').dumps(valid),quote=True)+'"><div data-pulse-series="{}"></div><div data-pulse-series="{}"></div></section><script src="/wp-content/themes/cyberdat/assets/js/threat-pulse.js?ver=123"></script>')
assert parser.version=='2.1' and parser.model and parser.series==2 and parser.asset
parser=module.HomeState();parser.feed('<section data-threat-pulse="2.1" data-pulse-periods="null"></section>');assert not parser.model
try:module.StagingRedirect().redirect_request(None,None,302,'',{},'https://example.invalid/')
except RuntimeError:pass
else:raise AssertionError('External credential redirect accepted')
print('PASS: distinguish valid server period model, unavailable model and refused external redirect without real HTTP')

assert module.basic_password_valid('TEST only ASCII')
assert module.basic_password_valid(' Тест only Unicode ')
for value in ['', '\x16', 'TEST\r\n', 'TEST\x00', 'TEST\t', 'TEST\x7f']:
 assert not module.basic_password_valid(value)
print('PASS: console paste control characters rejected; Unicode and intentional spaces preserved; no secret fixture values')
client.event({'method':'Network.responseReceived','params':{'response':{'url':'https://staging.cyberdat.eu/wp-json/cyberdat-analytics/v1/records?group=severity&value=High&q=CVE-2026-12345','status':409},'type':'Fetch'}})
assert client.record_response=={'status':409,'group':'severity','value':'High','date':'','days':''}
assert 'q' not in client.record_response and 'headers' not in client.record_response
assert 'tap(\'[data-ta-refresh]\')' in source and 'RECORD DIAGNOSTIC' in source
print('PASS: actual drill HTTP status and filter recorded without search text or credentials; revision refresh is explicit and bounded')
