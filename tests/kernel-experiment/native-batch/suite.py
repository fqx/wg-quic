import argparse,json,os,pathlib,signal,time,traceback
from run_three import trial
root=pathlib.Path(__file__).parent
parser=argparse.ArgumentParser()
parser.add_argument('--resume',action='store_true')
parser.add_argument('--epoch',default='post-maintenance')
args=parser.parse_args()
events=open(root/'suite-events.jsonl','a',buffering=1)
def event(**j):events.write(json.dumps(dict(time_ns=time.time_ns(),epoch=args.epoch,**j))+'\n')
def stop(signum,frame):raise KeyboardInterrupt('graceful stop signal '+str(signum))
signal.signal(signal.SIGINT,stop);signal.signal(signal.SIGTERM,stop)
def completed(arch,size,interval,duration,label):
 for p in (root/'results').glob('*/summary.json'):
  j=json.loads(p.read_text())
  if (j['arch'],j['size'],j['interval'],j['duration'],j['label'])==(arch,size,interval,duration,label):return True
 return False
def one(arch,size,interval,duration,label):
 if args.resume and completed(arch,size,interval,duration,label):
  event(event='resume_skip_complete',arch=arch,size=size,interval=interval,label=label);return
 if (root/'PAUSE').exists():raise KeyboardInterrupt('PAUSE marker')
 event(event='start',arch=arch,size=size,interval=interval,duration=duration,label=label,trace=False)
 try:
  s=trial(arch,size,interval,duration,10,20,label)
  event(event='done',trial=s['trial'],arch=arch,size=size,interval=interval,duration=duration,label=label,goodput=s['goodput_mbps'],loss=s['loss'])
 except Exception as e:
  event(event='failure',arch=arch,size=size,interval=interval,label=label,error=repr(e));traceback.print_exc()
conditions=[(1200,'1ms'),(1424,'1ms'),(1200,'16.667ms'),(1424,'16.667ms')]
try:
 for rep in range(3):
  for offset in range(4):
   z,i=conditions[(offset+rep)%4]
   for a in ['ABC','BCA','CAB'][rep]:one(a,z,i,60,'formal-post-r'+str(rep+1))
 for a in 'CAB':one(a,1424,'16.667ms',180,'confirmation')
 event(event='suite_finished')
except KeyboardInterrupt as e:
 event(event='graceful_pause',reason=str(e))
 raise SystemExit(130)
