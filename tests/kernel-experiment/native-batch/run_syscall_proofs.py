import os,signal
import json,pathlib,time,traceback
from run_three import trial
r=pathlib.Path(__file__).parent
(r/'proof.pid').write_text(str(os.getpid()))
def graceful_stop(signum,frame):raise KeyboardInterrupt('stop signal '+str(signum))
signal.signal(signal.SIGTERM,graceful_stop)
signal.signal(signal.SIGINT,graceful_stop)
events=open(r/'proof-events.jsonl','a',buffering=1)
for size,interval in [(1200,'1ms'),(1424,'16.667ms')]:
 for arch in ['B','C']:
  events.write(json.dumps(dict(event='start',arch=arch,size=size,interval=interval,time_ns=time.time_ns()))+'\n')
  try:
   s=trial(arch,size,interval,6,2,20,'post-syscall-proof',trace=True)
   events.write(json.dumps(dict(event='done',trial=s['trial'],time_ns=time.time_ns()))+'\n')
  except Exception as e:
   events.write(json.dumps(dict(event='failure',error=repr(e),time_ns=time.time_ns()))+'\n');traceback.print_exc()
events.write(json.dumps(dict(event='finished',time_ns=time.time_ns()))+'\n')
