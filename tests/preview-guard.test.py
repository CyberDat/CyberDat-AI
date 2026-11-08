#!/usr/bin/env python3
"""Execute real guard, front-page branch, assets and MU template in isolated PHP processes."""
import json,subprocess
from pathlib import Path
script=Path(__file__).with_name('preview-guard-case.php')
stage={'env':'staging','path':'/var/www/cyberdat-staging/public/','preview':True,'auth':'fixture-user'}
cases=[('production default',{},False),('production with live flags only',{'env':'production','kev':True,'nvd':True},False),('production with every flag',dict(stage,env='production',playground=True,kev=True,nvd=True),False),('production path mislabeled local',{'env':'local','path':'/var/www/cyberdat/public/','playground':True},False),('playground local',{'env':'local','playground':True},True),('playground development',{'env':'development','playground':True},True),('playground string flag',{'env':'local','playground':'true'},False),('local no flag',{'env':'local'},False),('staging explicit',stage,True)]
for name,patch in [('flag missing',{'preview':None}),('flag false',{'preview':False}),('flag string',{'preview':'true'}),('wrong root',{'path':'/var/www/cyberdat/public/'}),('root traversal',{'path':'/var/www/cyberdat-staging/public/../public/'}),('no Basic Auth',{'auth':''}),('bad auth value',{'auth':[]}),('HTTP home',{'home':'http://staging.cyberdat.eu/'}),('production home',{'home':'https://cyberdat.eu/'}),('production siteurl',{'site':'https://cyberdat.eu/'}),('URL userinfo',{'home':'https://user:placeholder@staging.cyberdat.eu/'}),('unexpected port',{'home':'https://staging.cyberdat.eu:8443/'}),('unexpected path',{'home':'https://staging.cyberdat.eu/subdir/'}),('query in URL',{'home':'https://staging.cyberdat.eu/?preview=1'}),('Playground on VPS',{'playground':True}),('local staging flag',{'env':'local'})]:
 c=dict(stage,**patch)
 if c.get('preview') is None:c.pop('preview',None)
 cases.append((name,c,False))
# Enabling preview never grants live API permission. Explicit live flags only in staging.
cases += [('explicit staging live permission',dict(stage,kev=True,nvd=True),True),('Playground still blocks live flags',{'env':'local','playground':True,'kev':True,'nvd':True},True)]
for name,c,expected in cases:
 q=subprocess.run(['php8.4',str(script),json.dumps(c)],capture_output=True,text=True)
 assert q.returncode==0,(name,q.stderr)
 d=json.loads(q.stdout)
 assert d['allowed']==expected and d['html_preview']==expected and d['css']==expected and d['safe_index']==(not expected),(name,d)
 expected_live=name=='explicit staging live permission'
 assert d['kev']==expected_live and d['nvd']==expected_live,(name,'live permission',d)
 safety=c.get('env')=='staging' and c.get('path')=='/var/www/cyberdat-staging/public/'
 assert d['mail_block']==safety,(name,'mail',d)
 if safety:assert d['robots']=={'noindex':True,'nofollow':True},(name,d)
 print('PASS',name)
print(len(cases),'guard/context cases passed')
