"""Execute the browser harness event handler without launching a browser/network."""
import importlib.util,pathlib
p=pathlib.Path(__file__).resolve().parents[1]/'deploy/research-0.8.2/capture-research.py'
spec=importlib.util.spec_from_file_location('research_browser',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def client():
 c=m.DevTools.__new__(m.DevTools);c.id=0;c.console_errors=0;c.runtime_errors=0;c.send=lambda data:None;c.authorization='';return c
def log(c,host,reason='net::ERR_BLOCKED_BY_CLIENT'):
 c.event({'method':'Log.entryAdded','params':{'entry':{'level':'error','source':'network','url':'https://'+host+'/avatar/redacted','text':'Failed to load resource: '+reason}}})
c=client();log(c,'secure.gravatar.com');assert c.console_errors==1 # Never assume arbitrary errors are intentional.
c=client();c.event({'method':'Fetch.requestPaused','params':{'requestId':'fixture','request':{'url':'https://secure.gravatar.com/avatar/redacted'}}});log(c,'secure.gravatar.com');assert c.console_errors==0 and c.expected_external_avatar_blocks==1
log(c,'secure.gravatar.com','net::ERR_CONNECTION_REFUSED');assert c.console_errors==1
log(c,'other.example');assert c.console_errors==2
c.event({'method':'Runtime.exceptionThrown','params':{'exceptionDetails':{}}});assert c.runtime_errors==1
assert len(c.console_entries)==3
print('PASS: only proven harness-blocked Gravatar requests classified separately; unrelated network and JS errors remain failures')
