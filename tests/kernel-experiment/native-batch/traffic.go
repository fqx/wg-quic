package main

import (
 "encoding/binary"
 "encoding/json"
 "flag"
 "fmt"
 "net"
 "os"
 "os/signal"
 "sort"
 "syscall"
 "time"
)

type Result struct {
 Mode string `json:"mode"`
 Packets uint64 `json:"packets"`
 Bytes uint64 `json:"bytes"`
 Errors uint64 `json:"errors"`
 Duplicates uint64 `json:"duplicates"`
 P50 float64 `json:"p50_ms"`
 P95 float64 `json:"p95_ms"`
 P99 float64 `json:"p99_ms"`
 Max float64 `json:"max_ms"`
 Seconds float64 `json:"seconds"`
 StartNS int64 `json:"start_ns"`
 EndNS int64 `json:"end_ns"`
 MaxLateness float64 `json:"max_tick_lateness_ms"`
 LateTicks uint64 `json:"ticks_later_than_interval"`
 BurstMax int `json:"max_packets_per_tick"`
}

func main() {
 mode:=flag.String("mode","receive","")
 addr:=flag.String("addr","10.66.0.2:49000","")
 size:=flag.Int("size",1200,"")
 mbps:=flag.Float64("mbps",20,"")
 interval:=flag.Duration("interval",time.Millisecond,"")
 warm:=flag.Duration("warmup",10*time.Second,"")
 duration:=flag.Duration("duration",60*time.Second,"")
 flag.Parse()
 if *mode=="send" { send(*addr,*size,*mbps,*interval,*warm,*duration);return }
 receive(*addr)
}

func send(addr string,size int,mbps float64,interval,warm,duration time.Duration) {
 c,err:=net.Dial("udp4",addr);if err!=nil{panic(err)};defer c.Close()
 b:=make([]byte,size);for i:=24;i<size;i++{b[i]=byte(i*31+17)}
 r:=Result{Mode:"send"};seq:=uint64(0)
 start:=time.Now();steady:=start.Add(warm);end:=steady.Add(duration)
 r.StartNS=steady.UnixNano();r.EndNS=end.UnixNano();r.Seconds=duration.Seconds()
 rate:=mbps*1e6/8/float64(size)
 sent:=0;next:=start
 for next.Before(end) {
  if wait:=time.Until(next);wait>0{time.Sleep(wait)}
  late:=time.Since(next);if late.Seconds()*1000>r.MaxLateness{r.MaxLateness=late.Seconds()*1000};if late>interval{r.LateTicks++}
  target:=int(next.Sub(start).Seconds()*rate)
  if target-sent>r.BurstMax{r.BurstMax=target-sent}
  phase:=uint64(0);now:=time.Now();if !now.Before(steady)&&now.Before(end){phase=1}
  for sent<target {
   binary.LittleEndian.PutUint64(b,seq);binary.LittleEndian.PutUint64(b[8:],uint64(time.Now().UnixNano()));binary.LittleEndian.PutUint64(b[16:],phase)
   n,e:=c.Write(b);if phase==1{if e!=nil||n!=size{r.Errors++}else{r.Packets++;r.Bytes+=uint64(n)}}
   seq++;sent++
  }
  next=next.Add(interval)
 }
 json.NewEncoder(os.Stdout).Encode(r)
}

func receive(addr string) {
 a,e:=net.ResolveUDPAddr("udp4",addr);if e!=nil{panic(e)}
 c,e:=net.ListenUDP("udp4",a);if e!=nil{panic(e)};defer c.Close();c.SetReadBuffer(4<<20)
 stop:=make(chan os.Signal,1);signal.Notify(stop,syscall.SIGTERM,os.Interrupt)
 go func(){<-stop;c.Close()}()
 r:=Result{Mode:"receive"};lat:=[]float64{};seen:=map[uint64]bool{}
 b:=make([]byte,65536);fmt.Fprintln(os.Stderr,"READY")
 for {n,_,err:=c.ReadFromUDP(b);if err!=nil{break};now:=time.Now().UnixNano()
  if n<24{r.Errors++;continue};if binary.LittleEndian.Uint64(b[16:])!=1{continue}
  seq:=binary.LittleEndian.Uint64(b);if seen[seq]{r.Duplicates++;continue};seen[seq]=true
  bad:=false;for i:=24;i<n;i++{if b[i]!=byte(i*31+17){bad=true;break}};if bad{r.Errors++;continue}
  sent:=int64(binary.LittleEndian.Uint64(b[8:]));if r.StartNS==0{r.StartNS=sent};r.EndNS=sent
  r.Packets++;r.Bytes+=uint64(n);lat=append(lat,float64(now-sent)/1e6)
 }
 if len(lat)>0{sort.Float64s(lat);r.P50=lat[len(lat)/2];r.P95=lat[(len(lat)-1)*95/100];r.P99=lat[(len(lat)-1)*99/100];r.Max=lat[len(lat)-1]}
 r.Seconds=float64(r.EndNS-r.StartNS)/1e9
 json.NewEncoder(os.Stdout).Encode(r)
}
