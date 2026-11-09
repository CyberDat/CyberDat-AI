"""Run the real common wait function against offline HTTP/UI states; no browser/network."""
import ast,base64,json,pathlib,tempfile
source=(pathlib.Path(__file__).resolve().parents[1]/'deploy/analytics-2.1/capture-analytics.py').read_text();tree=ast.parse(source);fn=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='await_records');compiled=compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'offline-common-wait','exec')
class Clock:
 def __init__(self):self.now=0
 def monotonic(self):return self.now
 def sleep(self,s):self.now+=s
class Browser:
 def __init__(self,states):self.states=list(states);self.record_response={'status':self.states[0]};self.runtime_errors=0;self.taps=0
 def evaluate(self,expression):
  if 'let state=' in expression:return {'dialogOpen':True,'statusClass':'failure'}
  if 'matching records' in expression:return self.record_response['status']==200
  return self.record_response['status'] in (409,503)
 def command(self,*args):return {'data':''}
 def tap(self,selector):
  assert selector=='[data-ta-refresh]';self.taps+=1
  if len(self.states)>1:self.states.pop(0)
  self.record_response={'status':self.states[0]}
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
for states,passed,refreshes in [([200],True,0),([409,200],True,1),([503,503,200],True,2),([500],False,0),([409,409],False,1),([503]*8,False,4)]:
 with tempfile.TemporaryDirectory() as temp:
  browser=Browser(states);clock=Clock();env={'print':lambda *a,**k:None,'cdp':browser,'time':clock,'tap':browser.tap,'wait':lambda *a:True,'width':1920,'info':{},'json':json,'output':pathlib.Path(temp),'base64':base64,'need':need};exec(compiled,env)
  try:env['await_records']('offline-fixture');actual=True
  except RuntimeError:actual=False
  assert actual==passed and browser.taps==refreshes,(states,actual,browser.taps)
  assert clock.now<=100
  if not passed:assert (pathlib.Path(temp)/'record-failure.json').is_file()
print('PASS: all record phases share strict bounded handling; normal data, one conflict refresh, producer-busy retry, unexpected errors and persistent failures')
assert source.count('def await_records(')==1 and 'Day/period drill request failed' not in source
