import argparse, json, os, pathlib, shutil, signal, subprocess as sp, time, traceback

ROOT=pathlib.Path('/root/wg-quic-batch-experiment')
BIN=ROOT/'bin'
RESULTS=ROOT/'results'
HZ=os.sysconf('SC_CLK_TCK')
NS=['wgq-ab-a','wgq-ab-b']

def run(args, **kw):
    return sp.run(args, check=True, text=True, stdout=sp.PIPE, stderr=sp.PIPE, **kw).stdout.strip()

def ip(ns,*args): return run(['ip','-n',ns,*args])
def nex(ns,*args): return run(['ip','netns','exec',ns,*args])

def snap(pids):
    s={'time_ns':time.time_ns(),'cpu':list(map(int,pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:])),'proc':{},'mem':{},'softnet':[]}
    sched=[l.split() for l in pathlib.Path('/proc/schedstat').read_text().splitlines() if l.startswith('cpu')]
    s['ctxt']=int(next(l.split()[1] for l in pathlib.Path('/proc/stat').read_text().splitlines() if l.startswith('ctxt ')))
    s['sched_runtime_ns']=sum(int(l[-3]) for l in sched)
    s['sched_wait_ns']=sum(int(l[-2]) for l in sched)
    for line in pathlib.Path('/proc/meminfo').read_text().splitlines():
        k,v=line.split(':',1)
        if k in ['MemAvailable','MemFree','Slab','SReclaimable','SUnreclaim','SwapFree']:
            s['mem'][k]=int(v.split()[0])
    for name,p in pids.items():
        try:
            f=pathlib.Path(f'/proc/{p.pid}/stat').read_text().rsplit(')',1)[1].split()
            s['proc'][name]={'user':int(f[11]),'system':int(f[12]),'rss_pages':int(f[21])}
        except FileNotFoundError: pass
    for l in pathlib.Path('/proc/net/softnet_stat').read_text().splitlines():
        s['softnet'].append([int(x,16) for x in l.split()])
    return s

def cleanup(procs,owned):
    for p in procs:
        if p.poll() is None: p.send_signal(signal.SIGTERM)
    for p in procs:
        try:p.wait(timeout=10)
        except sp.TimeoutExpired:p.kill();p.wait()
    for ns in owned:
        run(['ip','netns','delete',ns])

def trial(arch,size,interval,duration=60,warmup=10,mbps=20,label='',impair=False,badpsk=False,trace=False,badkey=False):
    ident=f'{time.strftime("%Y%m%dT%H%M%S")}-{arch}-{size}-{interval}-{label}'
    out=RESULTS/ident;out.mkdir(parents=True)
    secrets=pathlib.Path('/run')/ident;secrets.mkdir(mode=0o700)
    procs=[];owned=[];files=[]
    spec=dict(arch=arch,size=size,interval=interval,duration=duration,warmup=warmup,mbps=mbps,label=label,HZ=HZ,impair=impair,badpsk=badpsk,trace=trace,badkey=badkey)
    (out/'spec.json').write_text(json.dumps(spec,indent=2))
    try:
        existing=run(['ip','netns','list']).splitlines()
        assert not any(x.split()[0] in NS for x in existing), 'Own test namespace unexpectedly exists'
        for ns in NS:run(['ip','netns','add',ns]);owned.append(ns);ip(ns,'link','set','lo','up')
        run(['ip','link','add','abva','type','veth','peer','name','abvb'])
        run(['ip','link','set','abva','netns',NS[0]]);run(['ip','link','set','abvb','netns',NS[1]])
        for j,ns in enumerate(NS):
            v=['abva','abvb'][j];ip(ns,'addr','add',f'10.77.0.{j+1}/30','dev',v);ip(ns,'link','set',v,'mtu','1500','up')
        for name in ['a','b']:
            (secrets/f'{name}.key').write_text(run(['wg','genkey'])+'\n')
            os.chmod(secrets/f'{name}.key',0o600)
        (secrets/'psk.key').write_text(run(['wg','genpsk'])+'\n');os.chmod(secrets/'psk.key',0o600)
        pubs=[run(['wg','pubkey'],input=(secrets/f'{name}.key').read_text()) for name in ['a','b']]
        if impair:
            for j,ns in enumerate(NS):
                nex(ns,'tc','qdisc','add','dev',['abva','abvb'][j],'root','netem','delay','4ms','1ms','loss','2%','reorder','10%','25%')
        if badpsk:
            (secrets/'wrong.key').write_text(run(['wg','genpsk'])+'\n');os.chmod(secrets/'wrong.key',0o600)
        wrongpub=run(['wg','pubkey'],input=run(['wg','genkey'])+'\n') if badkey else None
        pids={}
        for j,ns in enumerate(NS):
            name=['a','b'][j];iface=['wgqa','wgqb'][j];peer=1-j
            peerpub=wrongpub if badkey and j==1 else pubs[peer]
            if arch in ['B','C']:
                ip(ns,'link','add',iface,'type','wireguard')
                args=['wg','set',iface,'private-key',str(secrets/f'{name}.key'),'listen-port','51820','peer',peerpub,'preshared-key',str(secrets/('wrong.key' if badpsk and j==1 else 'psk.key')),'allowed-ips',f'10.66.0.{peer+1}/32']
                if j==0:args+=['endpoint','127.0.0.1:51821']
                nex(ns,*args)
                cfg={'interface':iface,'kernel_endpoint':'127.0.0.1:51820','bootstrap_listen':'127.0.0.1:51821','peer_quic_endpoint':f'10.77.0.{peer+1}:{40001+peer}','quic_listen_port':40001+j,'peer_public_key':peerpub,'test_private_key_file':str(secrets/f'{name}.key'),'test_preshared_key_file':str(secrets/'psk.key'),'fec_mode':'auto','obfs_mode':'salamander'}
                cfgpath=secrets/f'{name}.json';cfgpath.write_text(json.dumps(cfg));os.chmod(cfgpath,0o600)
                cmd=[str(BIN/({'B':'B-kernel-original','C':'C-kernel-batch'}[arch])),'-config',str(cfgpath),'-stats-interval','0']
            else:
                cfg='[Interface]\nPrivateKey = '+(secrets/f'{name}.key').read_text().strip()+f'\nListenPort = {40001+j}\nMTU = 1500\n# wg-quic: congestion=model\n# wg-quic: fec=auto\n# wg-quic: obfs=salamander\n\n[Peer]\nPublicKey = '+pubs[peer]+'\nPresharedKey = '+(secrets/'psk.key').read_text().strip()+f'\nAllowedIPs = 10.66.0.{peer+1}/32\n'
                if j==0:cfg+=f'Endpoint = 10.77.0.{peer+1}:{40001+peer}\n'
                cfgpath=secrets/f'{name}.conf';cfgpath.write_text(cfg);os.chmod(cfgpath,0o600)
                cmd=[str(BIN/'A-baseline'),'run',str(cfgpath),'--name',iface]
            log=open(out/f'{name}.log','w');files.append(log)
            env=os.environ.copy();env.update(GOMAXPROCS='1',GOMEMLIMIT='192MiB')
            p=sp.Popen(['ip','netns','exec',ns,*cmd],env=env,stdout=log,stderr=sp.STDOUT)
            procs.append(p);pids[name]=p
            for t in range(100):
                if p.poll() is not None:raise RuntimeError(f'{name} endpoint exited, see log')
                try:ip(ns,'link','show',iface);break
                except sp.CalledProcessError:time.sleep(.1)
            else:raise RuntimeError('TUN not created')
            ip(ns,'addr','add',f'10.66.0.{j+1}/32','dev',iface);ip(ns,'link','set',iface,'mtu','1500','up');ip(ns,'route','add',f'10.66.0.{peer+1}/32','dev',iface)
        time.sleep(1)
        if badpsk or badkey:
            failed=sp.run(['ip','netns','exec',NS[0],'ping','-c','3','-W','1','10.66.0.2'],stdout=sp.PIPE,stderr=sp.STDOUT,text=True)
            (out/'ping-rejected.txt').write_text(failed.stdout)
            assert failed.returncode != 0
            for j,ns in enumerate(NS):
                text=nex(ns,'wg','show',['wgqa','wgqb'][j],'latest-handshakes')
                assert int(text.split()[-1])==0
                (out/f'{j}-handshake-rejected.txt').write_text(text)
            cleanup(procs,owned);owned=[]
            for f in files:f.flush()
            for name in (['a','b'] if badkey else ['a']):
                assert '"authenticated":true' not in (out/f'{name}.log').read_text().replace(' ','')
            result={**spec,'trial':ident,'kernel_handshakes_zero':True,'ping_rejected':True,'responder_authentication_is_not_full_handshake':badpsk}
            (out/'summary.json').write_text(json.dumps(result,indent=2))
            print(json.dumps(result),flush=True)
            return result
        ping=nex(NS[0],'ping','-c','10','-i','0.2','-W','2','10.66.0.2');(out/'ping.txt').write_text(ping)
        if arch in ['B','C']:
            for j,ns in enumerate(NS):
                text=nex(ns,'wg','show',['wgqa','wgqb'][j],'latest-handshakes')
                assert int(text.split()[-1])>0
                (out/f'{j}-handshake.txt').write_text(text)
        for j,ns in enumerate(NS):
            (out/f'{j}-snmp-start.txt').write_text(nex(ns,'cat','/proc/net/snmp'))
        recout=open(out/'receiver.json','w');recerr=open(out/'receiver.err','w');files.extend([recout,recerr])
        rec=sp.Popen(['ip','netns','exec',NS[1],str(BIN/'traffic'),'-mode','receive'],stdout=recout,stderr=recerr);procs.append(rec);pids['receiver']=rec
        time.sleep(.3)
        txout=open(out/'sender.json','w');files.append(txout)
        send=sp.Popen(['ip','netns','exec',NS[0],str(BIN/'traffic'),'-mode','send','-size',str(size),'-mbps',str(mbps),'-interval',interval,'-warmup',f'{warmup}s','-duration',f'{duration}s'],stdout=txout,stderr=sp.STDOUT);procs.append(send);pids['sender']=send
        tracer=None
        if trace:
            fdmap={}
            for name,p in pids.items():
                if name not in ['a','b']:continue
                udp=pathlib.Path(f'/proc/{p.pid}/net/udp').read_text()
                fds={}
                for fd in pathlib.Path(f'/proc/{p.pid}/fd').iterdir():
                    try:fds[fd.name]=str(fd.readlink())
                    except FileNotFoundError:pass
                fdmap[name]={'pid':p.pid,'udp':udp,'fds':fds}
            (out/'trace-fd-map.json').write_text(json.dumps(fdmap,indent=2))
            calls='recvmmsg,sendmmsg,recvfrom,sendto,recvmsg,sendmsg,read,write,readv,writev'
            tracer=sp.Popen(['strace','-ff','-ttt','-e','trace='+calls,'-e','raw='+calls,'-o',str(out/'syscalls'),'-p',str(pids['a'].pid),'-p',str(pids['b'].pid)],stdout=sp.DEVNULL,stderr=open(out/'strace.stderr','w'))
            procs.append(tracer)
        samples=[]
        while send.poll() is None:
            samples.append(snap(pids));time.sleep(.25)
        assert send.returncode==0
        samples.append(snap(pids));time.sleep(2);rec.terminate();rec.wait(timeout=10)
        if tracer is not None:
            tracer.send_signal(signal.SIGINT);tracer.wait(timeout=10)
        for j,ns in enumerate(NS):
            if impair:(out/f'{j}-netem-end.txt').write_text(nex(ns,'tc','-s','qdisc','show','dev',['abva','abvb'][j]))
            (out/f'{j}-snmp-end.txt').write_text(nex(ns,'cat','/proc/net/snmp'))
        (out/'samples.json').write_text(json.dumps(samples))
        cleanup(procs,owned);owned=[]
        for f in files:f.flush()
        tx=json.loads((out/'sender.json').read_text());rx=json.loads((out/'receiver.json').read_text())
        steady=[s for s in samples if tx['start_ns']<=s['time_ns']<=tx['end_ns']]
        assert len(steady)>2
        first,last=steady[0],steady[-1];seconds=(last['time_ns']-first['time_ns'])/1e9
        dc=[b-a for a,b in zip(first['cpu'],last['cpu'])];busy=sum(dc[i] for i in [0,1,2,5,6])/HZ
        summary={**spec,'trial':ident,'tx':tx,'rx':rx,'loss':1-rx['packets']/max(1,tx['packets']),'goodput_mbps':rx['bytes']*8/duration/1e6,'sample_seconds':seconds,'guest_busy_seconds':busy,'guest_cpu_pct_one_core':busy/seconds*100,'guest_cpu_seconds_per_MB':busy/(rx['bytes']/1e6)*(duration/seconds),'guest_user_seconds':dc[0]/HZ,'guest_system_seconds':dc[2]/HZ,'guest_softirq_seconds':dc[6]/HZ,'guest_steal_seconds':dc[7]/HZ,'guest_cpu_delta_jiffies':dc,'processes':{}}
        for name in ['a','b','sender','receiver']:
            if name in first['proc'] and name in last['proc']:
                a,b=first['proc'][name],last['proc'][name]
                summary['processes'][name]={'user_seconds':(b['user']-a['user'])/HZ,'system_seconds':(b['system']-a['system'])/HZ,'max_rss_kib':max(s['proc'].get(name,{}).get('rss_pages',0) for s in steady)*os.sysconf('SC_PAGE_SIZE')/1024}
        summary['measured_process_cpu_seconds']=sum(p['user_seconds']+p['system_seconds'] for p in summary['processes'].values())
        summary['guest_minus_measured_process_cpu_seconds']=busy-summary['measured_process_cpu_seconds']
        precise=(last['sched_runtime_ns']-first['sched_runtime_ns'])/1e9
        summary['guest_ctxt_delta']=last['ctxt']-first['ctxt']
        summary['guest_ctxt_per_MB']=summary['guest_ctxt_delta']/(rx['bytes']/1e6)*(duration/seconds)
        summary['guest_sched_runtime_seconds']=precise
        summary['guest_sched_cpu_pct_one_core']=precise/seconds*100
        summary['guest_sched_seconds_per_MB']=precise/(rx['bytes']/1e6)*(duration/seconds)
        summary['guest_sched_minus_process_cpu_seconds']=precise-summary['measured_process_cpu_seconds']
        summary['guest_sched_wait_seconds']=(last['sched_wait_ns']-first['sched_wait_ns'])/1e9
        summary['memory_start_kib']=first['mem'];summary['memory_end_kib']=last['mem']
        summary['softnet_drops_delta']=sum(x[1] for x in last['softnet'])-sum(x[1] for x in first['softnet'])
        summary['softnet_time_squeeze_delta']=sum(x[2] for x in last['softnet'])-sum(x[2] for x in first['softnet'])
        if arch in ['B','C']:
            for name in (['a','b'] if badkey else ['a']):
                assert '"authenticated":true' in (out/f'{name}.log').read_text().replace(' ',''), 'Kernel relay final authentication missing'
        for name in ['a','b']:
            lines=(out/f'{name}.log').read_text().splitlines()
            final=[l for l in lines if l.startswith('{') and 'authenticated' in l]
            if final:summary[name+'_relay_stats']=json.loads(final[-1])
        (out/'summary.json').write_text(json.dumps(summary,indent=2))
        print(json.dumps(summary),flush=True)
        return summary
    except Exception:
        (out/'failure.txt').write_text(traceback.format_exc());raise
    finally:
        cleanup(procs,owned)
        for f in files:f.close()
        shutil.rmtree(secrets)

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--arch',choices=['A','B','C']);a.add_argument('--size',type=int,default=1200);a.add_argument('--interval',default='1ms');a.add_argument('--duration',type=int,default=60);a.add_argument('--warmup',type=int,default=10);a.add_argument('--mbps',type=float,default=20);a.add_argument('--label',default='');a.add_argument('--impair',action='store_true');a.add_argument('--badpsk',action='store_true');a.add_argument('--trace',action='store_true');a.add_argument('--badkey',action='store_true');args=a.parse_args()
    RESULTS.mkdir(parents=True,exist_ok=True)
    trial(args.arch,args.size,args.interval,args.duration,args.warmup,args.mbps,args.label,args.impair,args.badpsk,args.trace,args.badkey)
