
import argparse,csv,importlib.util,json,pathlib,statistics,sys
r=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('previous_analysis',str(r/'previous_analysis.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
parser=argparse.ArgumentParser()
parser.add_argument('--phase',choices=['pre','post'],default='post')
args=parser.parse_args()
phase=args.phase
host=r/('host-metrics-batch-pre-maintenance.csv' if phase=='pre' else 'host-metrics-batch-post.csv')
rows=m.host_rows(host)
original_host_window=m.host_window
def extended_host_window(rows,start,end,margin=2):
 h=original_host_window(rows,start,end,margin)
 selected=[rows[k] for k in range(1,len(rows)) if rows[k-1]['t']>=start+margin and rows[k]['t']<=end-margin]
 runs=[v for x in selected for k,v in x['v'].items() if 'Vcpu(' in k and 'vmx-vcpu-' in k and 'wg-quic-ab-test' in k and k.rsplit(chr(92),1)[-1]=='% Run']
 h['vcpu_run_max_pct']=max(runs)
 h['interference_flags']=[]
 if h['vcpu_ready_max_pct']>5:h['interference_flags'].append('ready_over_5_percent')
 if h['costop_max_pct']>1:h['interference_flags'].append('costop_over_1_percent')
 if h['vm_swapped_max_MB']>0 or h['vm_swap_write_max_MB_s']>0:h['interference_flags'].append('host_vm_swap')
 if h['vcpu_run_max_pct']>=95:h['interference_flags'].append('vcpu_run_near_saturation')
 return h
m.host_window=extended_host_window
trials=[];failures=[]
for p in sorted((r/'results').glob('*/failure.txt')):failures.append(dict(trial=p.parent.name,error=p.read_text()))
for p in sorted((r/'results').glob('*/summary.json')):
 s=json.loads(p.read_text())
 if not(s['label'].startswith('formal-post-' if phase=='post' else 'formal-r') or (phase=='post' and s['label'].startswith('confirmation'))):continue
 start,end=s['tx']['start_ns']/1e9,s['tx']['end_ns']/1e9
 try:
  h=m.host_window(rows,start,end)
  rate=s['rx']['bytes']/1e6/s['duration']
  h['used_cost']=h['used_pct']/100/rate;h['run_cost']=h['run_pct']/100/rate
  vs=[m.host_window(rows,start,end,x)['used_pct']/100/rate for x in [1,2,3]]
  h['used_boundary_min']=min(vs);h['used_boundary_max']=max(vs)
  s['host']=h
 except Exception as e:failures.append(dict(trial=s['trial'],stage='analysis',error=repr(e)));continue
 s['endpoint_user_seconds']=sum(s['processes'][n]['user_seconds'] for n in ['a','b'])
 s['endpoint_system_seconds']=sum(s['processes'][n]['system_seconds'] for n in ['a','b'])
 s['endpoint_cpu_cost']=(s['endpoint_user_seconds']+s['endpoint_system_seconds'])/s['sample_seconds']/rate
 s['endpoint_rss_sum_MiB']=sum(s['processes'][n]['max_rss_kib'] for n in ['a','b'])/1024
 s['zero_loss']=s['loss']==0
 s['delivery_valid']=all(s[x]['errors']==0 for x in ['tx','rx']) and s['rx']['duplicates']==0 and abs(s['goodput_mbps']/20-1)<.005 and s['loss']<=.005
 s['host_coverage_valid']=h['covered_seconds']>=s['duration']*.6
 s['scheduler_below_processes']=s['guest_sched_runtime_seconds']+.1<s['measured_process_cpu_seconds']
 if s['arch']=='C':
  for side in ['a','b']:
   z=s[side+'_relay_stats']['stats']
   s[side+'_read_messages_per_batch']=z['local_read_messages']/max(1,z['local_read_batches'])
   s[side+'_read_multi_fraction']=z['local_read_multi_messages']/max(1,z['local_read_messages'])
   s[side+'_write_messages_per_batch']=z['local_write_messages']/max(1,z['local_write_batches'])
   s[side+'_write_multi_fraction']=z['local_write_multi_messages']/max(1,z['local_write_messages'])
 trials.append(s)
pairs=[]
for z,i in [(1200,'1ms'),(1424,'1ms'),(1200,'16.667ms'),(1424,'16.667ms')]:
 for label in sorted(set(s['label'] for s in trials)):
  ts={s['arch']:s for s in trials if(s['size'],s['interval'],s['label'])==(z,i,label)}
  if not all(a in ts for a in 'ABC'):continue
  for src,dst in [('B','C'),('A','C'),('A','B')]:
   a,b=ts[src],ts[dst]
   p=dict(size=z,interval=i,label=label,comparison=src+'->'+dst,source_trial=a['trial'],candidate_trial=b['trial'],valid=all(s['delivery_valid'] and s['host_coverage_valid'] for s in [a,b]),zero_loss=a['zero_loss'] and b['zero_loss'])
   for k,get in [('host_used',lambda s:s['host']['used_cost']),('host_run',lambda s:s['host']['run_cost']),('guest_sched',lambda s:s['guest_sched_seconds_per_MB']),('endpoint_cpu',lambda s:s['endpoint_cpu_cost']),('ctxt',lambda s:s['guest_ctxt_per_MB'])]:
    p[k+'_change_pct']=100*(get(b)/get(a)-1)
   p['host_boundary_min_pct']=100*(b['host']['used_boundary_min']/a['host']['used_boundary_max']-1)
   p['host_boundary_max_pct']=100*(b['host']['used_boundary_max']/a['host']['used_boundary_min']-1)
   pairs.append(p)
conditions=[]
for z,i in [(1200,'1ms'),(1424,'1ms'),(1200,'16.667ms'),(1424,'16.667ms')]:
 for comp in ['B->C','A->C','A->B']:
  ps=[p for p in pairs if p['size']==z and p['interval']==i and p['comparison']==comp and p['label'].startswith('formal-')]
  if not ps:continue
  c=dict(size=z,interval=i,comparison=comp,n=len(ps),valid=sum(p['valid'] for p in ps),zero_loss=sum(p['zero_loss'] for p in ps))
  for key in ['host_used_change_pct','host_run_change_pct','guest_sched_change_pct','endpoint_cpu_change_pct','ctxt_change_pct']:
   v=[p[key] for p in ps];c[key]=dict(median=statistics.median(v),min=min(v),max=max(v),values=v)
  c['boundary_envelope']=[min(p['host_boundary_min_pct'] for p in ps),max(p['host_boundary_max_pct'] for p in ps)]
  conditions.append(c)
data=dict(trials=trials,pairs=pairs,conditions=conditions,failures=failures)
(r/('analysis-'+phase+'.json')).write_text(json.dumps(data,indent=2))
for name,items in [('pairs',pairs),('trials',[dict(trial=s['trial'],arch=s['arch'],size=s['size'],interval=s['interval'],label=s['label'],duration=s['duration'],goodput=s['goodput_mbps'],loss=s['loss'],p95=s['rx']['p95_ms'],p99=s['rx']['p99_ms'],sched_cost=s['guest_sched_seconds_per_MB'],ctxt_per_MB=s['guest_ctxt_per_MB'],rss_MiB=s['endpoint_rss_sum_MiB'],delivery_valid=s['delivery_valid'],**{'host_'+k:v for k,v in s['host'].items() if not isinstance(v,list)}) for s in trials])]:
 if items:
  with(r/(name+'-'+phase+'.csv')).open('w')as f:
   w=csv.DictWriter(f,fieldnames=list(items[0]));w.writeheader();w.writerows(items)
print(json.dumps(dict(trials=len(trials),pairs=len(pairs),failures=len(failures),conditions=conditions),indent=2))
