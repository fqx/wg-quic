import argparse,csv,datetime,json,pathlib,statistics

ROOT=pathlib.Path('/root/wg-quic-native')
def avg(xs):return statistics.mean(xs) if xs else None
def med(xs):return statistics.median(xs) if xs else None
def percent(a,b):return 100*(a/b-1)

def host_rows(path):
    out=[]
    with path.open() as f:
        for r in csv.DictReader(f):
            if None in r or any(v is None for v in r.values()):continue
            try:
                stamp=datetime.datetime.strptime(next(iter(r.values())),'%m/%d/%Y %H:%M:%S').replace(tzinfo=datetime.timezone.utc).timestamp()
                vals={k:float(v) for k,v in list(r.items())[1:] if v!=''}
            except (ValueError,TypeError):continue
            if out:out[-1]['next']=stamp
            out.append(dict(t=stamp,v=vals))
    return out

def keyvalue(r,contains,suffix):
    matches=[v for k,v in r.items() if contains in k and k.endswith('\\'+suffix)]
    if len(matches)!=1:raise ValueError((contains,suffix,len(matches)))
    return matches[0]

def host_window(rows,start,end,margin=2):
    selected=[]
    for i in range(1,len(rows)):
        prev,row=rows[i-1],rows[i]
        if prev['t']>=start+margin and row['t']<=end-margin:
            selected.append((row,row['t']-prev['t']))
    assert selected,('No host samples',start,end,margin)
    weight=sum(dt for _,dt in selected)
    def weighted(fn):return sum(fn(x['v'])*dt for x,dt in selected)/weight
    vm=':wg-quic-ab-test)'
    def vmcpu(v,name):return next(x for k,x in v.items() if 'Group Cpu(' in k and vm in k and k.endswith('\\'+name))
    def vmmem(v,name):return next(x for k,x in v.items() if 'Group Memory(' in k and vm in k and k.endswith('\\'+name))
    def vcpuready(v):return [x for k,x in v.items() if 'Vcpu(' in k and 'vmx-vcpu-' in k and 'wg-quic-ab-test' in k and k.endswith('\\% Ready')]
    result={
      'sample_count':len(selected),'covered_seconds':weight,
      'used_pct':weighted(lambda v:vmcpu(v,'% Used')),
      'run_pct':weighted(lambda v:vmcpu(v,'% Run')),
      'used_unweighted_pct':avg([vmcpu(x['v'],'% Used') for x,_ in selected]),
      'group_ready_mean_pct':weighted(lambda v:vmcpu(v,'% Ready')),
      'vcpu_ready_max_pct':max(z for x,_ in selected for z in vcpuready(x['v'])),
      'vcpu_ready_sum_mean_pct':weighted(lambda v:sum(vcpuready(v))),
      'costop_max_pct':max(vmcpu(x['v'],'% CoStop') for x,_ in selected),
      'swap_wait_max_pct':max(vmcpu(x['v'],'% Swap Wait') for x,_ in selected),
      'vm_swapped_max_MB':max(vmmem(x['v'],'Swapped MBytes') for x,_ in selected),
      'vm_swap_write_max_MB_s':max(vmmem(x['v'],'Swap Written MBytes/sec') for x,_ in selected),
      'host_free_min_MB':min(keyvalue(x['v'],'\\Memory\\','Free MBytes') for x,_ in selected),
      'other_vm_used_mean_pct':weighted(lambda v:sum(x for k,x in v.items() if 'Group Cpu(' in k and any(':'+name+')' in k for name in ['DSM','HAOS','Hermes','pi-hole','v2ray']) and k.endswith('\\% Used'))),
      'hermes_used_mean_pct':weighted(lambda v:next(x for k,x in v.items() if 'Group Cpu(' in k and ':Hermes)' in k and k.endswith('\\% Used')))
    }
    return result

def analyze(root,host):
    rows=host_rows(host);trials=[]
    for p in sorted((root/'results').glob('*/summary.json')):
        s=json.loads(p.read_text())
        if not (s['label'].startswith('pair') or s['label']=='long-confirmation'):continue
        start,end=s['tx']['start_ns']/1e9,s['tx']['end_ns']/1e9
        h=host_window(rows,start,end)
        mb_s=s['rx']['bytes']/1e6/s['duration']
        h['used_cost']=h['used_pct']/100/mb_s
        h['run_cost']=h['run_pct']/100/mb_s
        variants=[host_window(rows,start,end,m) for m in [1,2,3]]
        h['used_cost_sensitivity']=[x['used_pct']/100/mb_s for x in variants]+[h['used_unweighted_pct']/100/mb_s]
        h['used_cost_min']=min(h['used_cost_sensitivity']);h['used_cost_max']=max(h['used_cost_sensitivity'])
        s['host']=h
        s['endpoint_user_cpu_s']=sum(s['processes'][x]['user_seconds'] for x in ['a','b'])
        s['endpoint_system_cpu_s']=sum(s['processes'][x]['system_seconds'] for x in ['a','b'])
        s['endpoint_cpu_cost']=(s['endpoint_user_cpu_s']+s['endpoint_system_cpu_s'])/s['sample_seconds']/mb_s
        s['endpoint_peak_rss_sum_MiB']=sum(s['processes'][x]['max_rss_kib'] for x in ['a','b'])/1024
        s['tick_below_measured_processes']=s['guest_busy_seconds']+0.1<s['measured_process_cpu_seconds']
        s['scheduler_below_measured_processes']=s['guest_sched_runtime_seconds']+0.1<s['measured_process_cpu_seconds']
        s['valid_delivery']=s['loss']==0 and s['rx']['errors']==0 and s['rx']['duplicates']==0 and s['tx']['errors']==0 and abs(s['goodput_mbps']/s['mbps']-1)<.005
        s['valid_host_coverage']=h['covered_seconds']>=.6*s['duration']
        trials.append(s)
    pairs=[]
    for size,interval in [(1200,'1ms'),(1424,'1ms'),(1200,'16.667ms'),(1424,'16.667ms')]:
        for label in ['pair1','pair2','pair3']+(['long-confirmation'] if (size,interval)==(1424,'16.667ms') else []):
            ts=[s for s in trials if s['size']==size and s['interval']==interval and s['label']==label]
            if len(ts)!=2:continue
            b=next(s for s in ts if s['arch']=='baseline');k=next(s for s in ts if s['arch']=='kernel')
            pair=dict(size=size,interval=interval,label=label,baseline=b['trial'],kernel=k['trial'],valid=b['valid_delivery'] and k['valid_delivery'] and b['valid_host_coverage'] and k['valid_host_coverage'] and not b['scheduler_below_measured_processes'] and not k['scheduler_below_measured_processes'])
            pair.update(host_used_change_pct=percent(k['host']['used_cost'],b['host']['used_cost']),host_run_change_pct=percent(k['host']['run_cost'],b['host']['run_cost']),guest_sched_change_pct=percent(k['guest_sched_seconds_per_MB'],b['guest_sched_seconds_per_MB']),endpoint_process_change_pct=percent(k['endpoint_cpu_cost'],b['endpoint_cpu_cost']),tick_change_pct=percent(k['guest_cpu_seconds_per_MB'],b['guest_cpu_seconds_per_MB']))
            pair['host_boundary_change_min_pct']=percent(k['host']['used_cost_min'],b['host']['used_cost_max']);pair['host_boundary_change_max_pct']=percent(k['host']['used_cost_max'],b['host']['used_cost_min'])
            pair['goodput_difference_pct']=percent(k['goodput_mbps'],b['goodput_mbps']);pairs.append(pair)
    conditions=[]
    for size,interval in [(1200,'1ms'),(1424,'1ms'),(1200,'16.667ms'),(1424,'16.667ms')]:
        ps=[p for p in pairs if p['size']==size and p['interval']==interval and p['label'].startswith('pair')]
        if not ps:continue
        c=dict(size=size,interval=interval,pairs=len(ps),valid_pairs=sum(x['valid'] for x in ps))
        for key in ['host_used_change_pct','host_run_change_pct','guest_sched_change_pct','endpoint_process_change_pct','tick_change_pct']:
            vs=[p[key] for p in ps];c[key]={'median':med(vs),'min':min(vs),'max':max(vs),'values':vs}
        c['host_boundary_change_envelope_pct']=[min(p['host_boundary_change_min_pct'] for p in ps),max(p['host_boundary_change_max_pct'] for p in ps)]
        for arch in ['baseline','kernel']:
            ts=[s for s in trials if s['size']==size and s['interval']==interval and s['arch']==arch and s['label'].startswith('pair')]
            c[arch]={'host_used_cost_mean':avg([s['host']['used_cost'] for s in ts]),'host_run_cost_mean':avg([s['host']['run_cost'] for s in ts]),'sched_cost_mean':avg([s['guest_sched_seconds_per_MB'] for s in ts]),'endpoint_cost_mean':avg([s['endpoint_cpu_cost'] for s in ts]),'endpoint_user_s_mean':avg([s['endpoint_user_cpu_s'] for s in ts]),'endpoint_system_s_mean':avg([s['endpoint_system_cpu_s'] for s in ts]),'endpoint_rss_MiB_median':med([s['endpoint_peak_rss_sum_MiB'] for s in ts]),'p99_ms_median':med([s['rx']['p99_ms'] for s in ts]),'goodput_Mbps_min':min(s['goodput_mbps'] for s in ts),'goodput_Mbps_max':max(s['goodput_mbps'] for s in ts),'loss_max':max(s['loss'] for s in ts),'vcpu_ready_max_pct':max(s['host']['vcpu_ready_max_pct'] for s in ts),'other_vm_used_mean_pct':avg([s['host']['other_vm_used_mean_pct'] for s in ts])}
        conditions.append(c)
    validation=[]
    for p in sorted(root.glob('accounting-validation*.json')):validation+=json.loads(p.read_text())
    for v in validation:
        ts=[s for s in trials if s['arch']==v['event']['arch'] and s['size']==v['event']['size'] and s['interval']==v['event']['interval'] and s['label']==f"pair{v['event']['rep']+1}"]
        v['within_steady_window']=bool(ts and v['a']['time_ns']>=ts[0]['tx']['start_ns'] and v['b']['time_ns']<=ts[0]['tx']['end_ns'])
    thread_validation=json.loads((root/'thread-accounting-validation.json').read_text()) if (root/'thread-accounting-validation.json').exists() else []
    for v in thread_validation:
        z=next((s for s in trials if s['trial']==v['trial']),None)
        v['within_steady_window']=bool(z and v['a']['time_ns']>=z['tx']['start_ns'] and v['b']['time_ns']<=z['tx']['end_ns'])
    return dict(generated_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),trials=trials,pairs=pairs,conditions=conditions,accounting_validation=validation,thread_accounting_validation=thread_validation,total_formal_received_bytes=sum(s['rx']['bytes'] for s in trials),total_formal_received_packets=sum(s['rx']['packets'] for s in trials),tick_underaccount_trials=sum(s['tick_below_measured_processes'] for s in trials),scheduler_underaccount_trials=sum(s['scheduler_below_measured_processes'] for s in trials),invalid_delivery_trials=sum(not s['valid_delivery'] for s in trials),invalid_host_coverage_trials=sum(not s['valid_host_coverage'] for s in trials))

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--root',type=pathlib.Path,default=ROOT);a.add_argument('--host',type=pathlib.Path,default=ROOT/'host-metrics-native.csv');args=a.parse_args()
    data=analyze(args.root,args.host);(args.root/'analysis.json').write_text(json.dumps(data,indent=2))
    with (args.root/'pairs.csv').open('w') as f:
        w=csv.DictWriter(f,fieldnames=list(data['pairs'][0]) if data['pairs'] else []);w.writeheader();w.writerows(data['pairs'])
    flat=[]
    for s in data['trials']:
        d={k:s[k] for k in ['trial','arch','size','interval','duration','label','goodput_mbps','loss','guest_busy_seconds','guest_user_seconds','guest_system_seconds','guest_softirq_seconds','guest_steal_seconds','guest_sched_runtime_seconds','guest_sched_seconds_per_MB','measured_process_cpu_seconds','guest_sched_minus_process_cpu_seconds','endpoint_user_cpu_s','endpoint_system_cpu_s','endpoint_cpu_cost','endpoint_peak_rss_sum_MiB','valid_delivery','valid_host_coverage','tick_below_measured_processes','scheduler_below_measured_processes']};d.update({'host_'+k:v for k,v in s['host'].items() if not isinstance(v,list)});d['p99_ms']=s['rx']['p99_ms'];d['sender_max_tick_lateness_ms']=s['tx']['max_tick_lateness_ms'];d['sender_late_ticks']=s['tx']['ticks_later_than_interval'];d['sender_max_packets_per_tick']=s['tx']['max_packets_per_tick'];flat.append(d)
    with (args.root/'trials.csv').open('w') as f:
        w=csv.DictWriter(f,fieldnames=list(flat[0]) if flat else []);w.writeheader();w.writerows(flat)
    print(json.dumps({k:data[k] for k in ['generated_utc','total_formal_received_bytes','tick_underaccount_trials','scheduler_underaccount_trials','invalid_delivery_trials','invalid_host_coverage_trials']}));print(json.dumps(data['conditions'],indent=2))
