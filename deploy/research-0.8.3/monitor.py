import sys,importlib.util,time,json,datetime
sys.dont_write_bytecode=True
from pathlib import Path
D=Path(__file__).parent;spec=importlib.util.spec_from_file_location('manager',D/'manage.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
# Only read SQL/unit state; wait for natural cycles. No sync or due-time changes.
end=time.time()+1600;last=0
while time.time()<end:
 minute=int(time.time()//60)
 if minute%5==1 and minute!=last:
  last=minute;o=m.snapshot();name=m.B/('observe-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json');name.write_text(json.dumps(o,indent=2));h=o['state'].get('health:nvd',{});w=o['state'].get('nvd_window') or {};cross=o['state'].get('discovery_window:crossref') or {};c=o['state'].get('health:crossref',{});print(json.dumps({'utc':o['utc'],'counts':o['db']['counts'],'nvd_success':h.get('last_success'),'nvd_error':h.get('last_error'),'scheduled_success':h.get('last_scheduled_success'),'time_progress':w.get('time_progress'),'checkpoint':o['state'].get('nvd_checkpoint'),'crossref_offset':cross.get('offset'),'crossref_error':c.get('last_error'),'crossref_success':c.get('last_success')}),flush=True)
 time.sleep(20)
print('Observation interval finished; no source/scheduler writes',flush=True)
