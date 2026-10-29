import pathlib,json,re,collections
r=pathlib.Path(__file__).parent
results=[]
for d in sorted((r/'results').iterdir()):
 if not(d/'trace-fd-map.json').exists():continue
 maps=json.loads((d/'trace-fd-map.json').read_text());sets=[]
 for name,m in maps.items():
  inodes=set()
  for line in m['udp'].splitlines()[1:]:
   f=line.split()
   if len(f)>9 and f[2]=='0100007F:CA6C':inodes.add(f[9])
  sets.append({int(fd) for fd,link in m['fds'].items() if link.startswith('socket:[') and link[8:-1] in inodes})
 if not sets or any(x!=sets[0] for x in sets):raise ValueError('Ambiguous process UDP FD mapping')
 local=sets[0];groups=collections.defaultdict(lambda:dict(calls=0,success_calls=0,packets=0,multi_packets=0,max_batch=0,eagain=0,other_errors=0,unresolved=0))
 for p in d.glob('syscalls.*'):
  if p.name.endswith('stderr'):continue
  for line in p.read_text().splitlines():
   a=re.search(r'(recvmmsg|sendmmsg|recvfrom|sendto|recvmsg|sendmsg|readv|writev|read|write)\((0x[0-9a-f]+|[0-9]+),',line)
   if not a or int(a[2],0) not in local:continue
   z=groups[a[1]];z['calls']+=1
   ret=re.search(r'= (-1|0x[0-9a-f]+|[0-9]+)(?:\s|$)',line)
   if not ret:z['unresolved']+=1;continue
   n=int(ret[1],0)
   if n<0:z['eagain' if 'EAGAIN' in line else 'other_errors']+=1;continue
   if n==0:continue
   packets=n if a[1] in ['recvmmsg','sendmmsg'] else 1
   z['success_calls']+=1;z['packets']+=packets;z['max_batch']=max(z['max_batch'],packets)
   if packets>1:z['multi_packets']+=packets
 for name,z in groups.items():
  z['calls_per_packet']=z['calls']/max(1,z['packets'])
  z['success_calls_per_packet']=z['success_calls']/max(1,z['packets'])
  z['packets_per_success_call']=z['packets']/max(1,z['success_calls'])
  z['multi_fraction']=z['multi_packets']/max(1,z['packets'])
 spec=json.loads((d/'spec.json').read_text())
 results.append(dict(trial=d.name,spec=spec,local_fds=sorted(local),groups=dict(groups),note='Intrusive trace: not CPU performance evidence. EAGAIN included in calls, unfinished/resumed lines retained as unresolved. First B traces missing read/write are incomplete, not zero-cost.'))
(r/'syscall-analysis.json').write_text(json.dumps(results,indent=2))
for z in results:
 if z['spec']['label']=='post-syscall-proof':print(z['trial'],json.dumps(z['groups']))
