import csv,hashlib,importlib.util,json,re,sys
from pathlib import Path
from audit_echo import packets

def audit(root,out):
    root,out=Path(root),Path(out);out.mkdir(parents=True,exist_ok=True)
    spec=importlib.util.spec_from_file_location('frozen_endpoint',root/'geneva_healthcheck.py')
    endpoint=importlib.util.module_from_spec(spec);spec.loader.exec_module(endpoint)
    rows=[];resets=[]
    for batch in sorted((root/'results').glob('http_*')):
        if batch.name=='http_handoff':continue
        for f in sorted(batch.glob('*.log')):
            text=f.read_text()
            events=[json.loads(l.split('ENDPOINT_RESULT ',1)[1]) for l in text.splitlines() if 'ENDPOINT_RESULT ' in l]
            assert len(events)==1,(f,len(events))
            event=events[0];o=event['observation'];d=event['diagnosis']
            assert endpoint.diagnose(o)==d,(f,'Diagnosis does not reproduce')
            ids=re.findall(r'INFO:\[([^\]]+)\] Fitness',text);assert len(ids)==1
            eid=ids[0]
            locations=list((root/'trials').glob('*/endpoint/'+eid+'.json'));assert len(locations)==1
            ep=locations[0];assert json.loads(ep.read_text())==event
            base=ep.parent.parent
            cl=(base/'logs'/(eid+'.client.log')).read_text()
            ce=(base/'logs'/(eid+'.censor.log')).read_text()
            se=(base/'logs'/(eid+'.server.log')).read_text()
            assert sum('ENDPOINT_RESULT ' in l for l in cl.splitlines())==1
            assert event==json.loads(next(l.split('ENDPOINT_RESULT ',1)[1] for l in cl.splitlines() if 'ENDPOINT_RESULT ' in l))
            code=int(f.with_suffix('.exitcode').read_text())
            valid=code==0 and 'Confirmed server listener' in se and not re.search(r'ERROR:|Traceback|Address already in use',text)
            fault=batch.name.startswith('http_faults')
            if fault:
                condition,trial=f.stem.rsplit('_',1);censor='censor2'
            else: censor,condition,trial=f.stem.split('_')
            expected_verified=(not fault and condition in ['benign','segment26'])
            if d['delivery_verified']:
                assert o['bytes_received']==endpoint.FILE_BYTES and o['status']==200
                assert o['sha256']==endpoint.REFERENCE_SHA256
            # Application policy is HTTP 200 + exact reference object.
            status_baseline=o['status']==200
            length_baseline=status_baseline and o['bytes_received']==o['expected_bytes']
            r=dict(batch='faults' if fault else 'comparison',censor=censor,condition=condition,
                   trial=int(trial),eid=eid,valid=valid,verified=d['delivery_verified'],
                   symptom=d['symptom'],root_cause=d['root_cause'],attribution=d['censorship_attribution'],
                   status=o['status'],bytes_received=o['bytes_received'],declared_bytes=o['declared_bytes'],
                   sha256=o['sha256'],error_kind=o['error_kind'],error_message=o['error_message'],
                   total_ms=o['total_ms'],censor_triggers=ce.count('Packet triggered censor:'),
                   http200_baseline=status_baseline,status_length_baseline=length_baseline,
                   expected_verified=expected_verified,endpoint_json=str(ep.relative_to(root)),
                   console_log=str(f.relative_to(root)))
            rows.append(r)
            
            if not fault and censor=='censor2' and condition in ['blocked','segment22']:
                ack=None;server_bytes=0
                for p in packets(base/'packets'/(eid+'_client.pcap')):
                    if p['dport']==18080 and p['flags']&16:ack=p['ack']
                    if p['sport']==18080 and p['length']>0:server_bytes+=p['length']
                    if p['sport']==18080 and p['flags']&4:
                        resets.append(dict(condition=condition,trial=int(trial),eid=eid,
                            rst_frame=p['frame'],rst_seq=p['seq'],prior_client_ack=ack,
                            seq_minus_ack=None if ack is None else ((p['seq']-ack+2**31)%2**32)-2**31,
                            prior_server_payload_bytes=server_bytes,checksum_valid=p['checksum_valid']))
                        break
    assert len(rows)==36 and all(r['valid'] for r in rows)
    for name,data in [('http_trial_results.csv',rows),('http_first_resets.csv',resets)]:
        with (out/name).open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=list(data[0]));w.writeheader();w.writerows(data)
    faults=[r for r in rows if r['batch']=='faults']
    summary=dict(trials=len(rows),valid=sum(r['valid'] for r in rows),
        comparison_trials=sum(r['batch']=='comparison' for r in rows),fault_trials=len(faults),
        http200_false_accepts_on_faults=sum(r['http200_baseline'] for r in faults),
        http200_and_length_false_accepts_on_faults=sum(r['status_length_baseline'] for r in faults),
        verified_false_accepts_on_faults=sum(r['verified'] for r in faults),
        causal_attribution='Not implemented: endpoint failures explicitly abstain on root cause')
    (out/'http_audit_summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))
    hashes=[]
    for p in sorted(root.rglob('*')):
        if p.is_file() and '__pycache__' not in str(p):hashes.append(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(root)))
    (out/'http_evidence_sha256.txt').write_text('\n'.join(hashes)+'\n')

if __name__=='__main__':audit(sys.argv[1],sys.argv[2])
