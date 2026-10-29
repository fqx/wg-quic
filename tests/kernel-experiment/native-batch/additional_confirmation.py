import os,signal
import json,pathlib,time,traceback
from run_three import trial
r=pathlib.Path(__file__).parent
(r/'additional.pid').write_text(str(os.getpid()))
def graceful_stop(signum,frame):raise KeyboardInterrupt('stop signal '+str(signum))
signal.signal(signal.SIGTERM,graceful_stop)
signal.signal(signal.SIGINT,graceful_stop)
events=open(r/'additional-events.jsonl','a',buffering=1)
def event(**j):events.write(json.dumps(dict(time_ns=time.time_ns(),**j))+'\n')
for a in 'BCA':
 event(event='start',arch=a,size=1200,interval='16.667ms',duration=180,label='confirmation-1200-frame')
 try:
  s=trial(a,1200,'16.667ms',180,10,20,'confirmation-1200-frame')
  event(event='done',arch=a,trial=s['trial'],goodput=s['goodput_mbps'],loss=s['loss'])
 except Exception as e:event(event='failure',arch=a,error=repr(e));traceback.print_exc()
event(event='finished')
