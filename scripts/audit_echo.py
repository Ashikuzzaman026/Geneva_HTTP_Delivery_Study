import csv, hashlib, json, re, socket, struct, sys
from pathlib import Path

def checksum(data):
    if len(data) % 2: data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while total >> 16: total = (total & 65535) + (total >> 16)
    return (~total) & 65535

def packets(path):
    data = path.read_bytes()
    endian = {'d4c3b2a1':'<','a1b2c3d4':'>'}[data[:4].hex()]
    assert struct.unpack(endian+'I', data[20:24])[0] == 1, 'Expected Ethernet'
    pos, frame = 24, 0
    while pos < len(data):
        sec, usec, length, original = struct.unpack(endian+'IIII',data[pos:pos+16])
        raw=data[pos+16:pos+16+length]; pos += 16+length; frame += 1
        if len(raw)<34 or raw[12:14] != b'\x08\x00': continue
        ip=raw[14:]; ihl=(ip[0]&15)*4
        if ip[9]!=6 or struct.unpack('!H',ip[6:8])[0]&0x1fff: continue
        total=struct.unpack('!H',ip[2:4])[0]; tcp=ip[ihl:total]
        if len(tcp)<20: continue
        sport,dport,seq,ack=struct.unpack('!HHII',tcp[:12]); hlen=(tcp[12]>>4)*4
        pseudo=ip[12:20]+b'\0\x06'+struct.pack('!H',len(tcp))
        yield dict(frame=frame,time=sec+usec/1e6,src=socket.inet_ntoa(ip[12:16]),
                   dst=socket.inet_ntoa(ip[16:20]),sport=sport,dport=dport,seq=seq,
                   ack=ack,flags=tcp[13],length=len(tcp)-hlen,
                   checksum_valid=checksum(pseudo+tcp)==0)

def main(root,out):
    root,out=Path(root),Path(out); out.mkdir(parents=True,exist_ok=True)
    rows=[]; reset_rows=[]
    for batch in sorted((root/'results').glob('final_censor*')):
        censor=re.search(r'final_(censor\d+)_',batch.name)[1]
        for log in sorted(batch.glob('*.log')):
            text=log.read_text(); condition,trial=log.stem.rsplit('_',1)
            ids=re.findall(r'INFO:\[([^\]]+)\] Fitness',text)
            assert len(ids)==1, (log,ids)
            eid=ids[0]
            client=list((root/'trials').glob('*/logs/'+eid+'.client.log'))
            censorlogs=list((root/'trials').glob('*/logs/'+eid+'.censor.log'))
            assert len(client)==len(censorlogs)==1
            cl,ce=client[0].read_text(),censorlogs[0].read_text()
            pcap=client[0].parent.parent/'packets'/(eid+'_client.pcap')
            assert pcap.is_file()
            done=re.findall(r'Complete echo exchanges: (\d+)/5',cl)
            assert len(done)==1
            complete=int(done[0]); matches=re.findall(r'Echo bytes: received=(\d+) expected=(\d+)',cl)
            equal=sum(a==b for a,b in matches)
            
            if complete==5: assert equal==5
            readiness='Confirmed server listener on port 18080' in text
            startup_error=bool(re.search(r'Address already in use|ConnectionRefusedError|Traceback|ERROR:',text))
            exitcode=int(log.with_suffix('.exitcode').read_text())
            valid=readiness and not startup_error and exitcode==0
            trigger=ce.count('Packet triggered censor:')
            records=list(packets(pcap)); latest_ack={}; data_end={}; incoming_rst=0
            for p in records:
                if p['sport']==18080 and p['length']>0 and not p['flags']&4:
                    k=(p['dst'],p['dport'],p['src'],p['sport'])
                    
                    data_end[k]=max(data_end.get(k,0),p['seq']+p['length'])
                if p['dport']==18080 and p['flags']&16:
                    latest_ack[(p['src'],p['sport'],p['dst'],p['dport'])]=(p['ack'],p['frame'])
                if p['sport']==18080 and p['flags']&4:
                    incoming_rst+=1
                    key=(p['dst'],p['dport'],p['src'],p['sport'])
                    expected,aframe=latest_ack.get(key,(None,None))
                    delta=None if expected is None else ((p['seq']-expected+2**31)%2**32)-2**31
                    reset_rows.append(dict(censor=censor,condition=condition,trial=trial,eid=eid,
                        rst_frame=p['frame'],rst_seq=p['seq'],prior_client_ack=expected,
                        prior_ack_frame=aframe,seq_minus_prior_ack=delta,
                        prior_observed_server_data_end=data_end.get(key),
                        seq_minus_observed_data_end=(None if key not in data_end else p['seq']-data_end[key]),
                        checksum_valid=p['checksum_valid']))
            rows.append(dict(censor=censor,condition=condition,trial=int(trial),eid=eid,
                valid=valid,complete_exchanges=complete,success=valid and complete==5,
                censor_triggers=trigger,incoming_rst=incoming_rst,
                fitness=float(re.findall(r'Fitness: (-?\d+(?:\.\d+)?)',cl)[-1]),
                client_pcap=str(pcap.relative_to(root)),console_log=str(log.relative_to(root))))
    assert len(rows)==24
    for name,data in [('trial_results.csv',rows),('reset_sequence_evidence.csv',reset_rows)]:
        with (out/name).open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=list(data[0]));w.writeheader();w.writerows(data)
    summary=[]
    for censor in ['censor1','censor2']:
        for condition in ['benign','blocked','segment22','segment26']:
            group=[r for r in rows if r['censor']==censor and r['condition']==condition]
            summary.append(dict(censor=censor,condition=condition,attempted=len(group),
                valid=sum(r['valid'] for r in group),success=sum(r['success'] for r in group),
                trials_with_detection=sum(r['censor_triggers']>0 for r in group)))
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))
    print('RST offsets for censor2 segment22:',sorted(set(r['seq_minus_prior_ack'] for r in reset_rows if r['censor']=='censor2' and r['condition']=='segment22')))
    print('All analyzed RST TCP checksums valid:',all(r['checksum_valid'] for r in reset_rows))
    manifest=[]
    for p in sorted(root.rglob('*')):
        if p.is_file(): manifest.append(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(root)))
    (out/'evidence_sha256.txt').write_text('\n'.join(manifest)+'\n')

if __name__=='__main__': main(sys.argv[1],sys.argv[2])
