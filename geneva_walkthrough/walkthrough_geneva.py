import argparse
import hashlib
import inspect
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default='results/geneva_walkthrough.json')
    args=parser.parse_args()
    root=Path.cwd()
    if not (root/'evolve.py').is_file() or not (root/'actions/strategy.py').is_file():
        raise SystemExit('Run from the existing Geneva checkout, not the package folder.')
    sys.path.insert(0,str(root))
    from scapy.all import IP,TCP,Raw
    import actions.utils
    import actions.strategy
    import actions.tree
    import actions.trigger
    import actions.fragment
    from layers.packet import Packet
    import actions.action
    import actions.duplicate
    import actions.drop
    import actions.tamper
    
    primitives=[actions.fragment.FragmentAction,actions.duplicate.DuplicateAction,
                actions.drop.DropAction,actions.tamper.TamperAction]
    for direction in ['out','in']:
        actions.action.ACTION_CACHE[direction]['terminal']=[
            (cls.__name__,cls) for cls in primitives if cls().applies(direction)]

    logger=logging.getLogger('offline_walkthrough');logger.addHandler(logging.NullHandler())
    payload=b'GET / HTTP/1.1\r\nHost: ultrasurf.example\r\nConnection: close\r\n\r\n'
    def packet(flags='PA'):
        return Packet(IP(src='192.0.2.10',dst='198.51.100.20')/
                      TCP(sport=40000,dport=18080,flags=flags,seq=1000,ack=2000)/Raw(load=payload))
    def run(dna,flags='PA',direction='out'):
        strategy=actions.utils.parse(dna,logger)
        result=strategy.act_on_packet(packet(flags),logger,direction=direction)
        return strategy,result
    def content(p):return bytes(p.packet[TCP].payload)
    results=[]
    def check(name,condition,evidence):
        if not condition:raise AssertionError(name+': '+str(evidence))
        results.append(dict(check=name,passed=True,evidence=evidence))
        print('PASS '+name)

   
    for n in [22,26]:
        dna='[TCP:flags:PA]-fragment{tcp:%d:True}-|' % n
        strategy,parts=run(dna)
        sizes=[len(content(p)) for p in parts]
        sequences=[p.packet[TCP].seq for p in parts]
        reconstructed=b''.join(content(p) for p in parts)
        check('split%d preserves stream bytes and TCP offsets' % n,
              len(parts)==2 and sizes==[n,len(payload)-n]
              and sequences==[1000,1000+n] and reconstructed==payload,
              dict(dna=str(strategy),lengths=sizes,sequences=sequences,
                   payloads=[content(p).decode('ascii') for p in parts]))
        keyword_present=[b'ultrasurf' in content(p) for p in parts]
        check('split%d keyword placement' % n,
              keyword_present==([False,True] if n==22 else [False,False]),
              dict(keyword_in_each_segment=keyword_present,
                   scope='Packet-local demonstration; not a claim about stream-reassembling censors'))

    dna='[TCP:flags:PA]-fragment{tcp:26:True}-|'
    _,parts=run(dna,flags='A')
    check('Nonmatching TCP flags bypass PA trigger',len(parts)==1 and content(parts[0])==payload,
          {'flags':'A','outgoing_packets':len(parts)})
    _,parts=run(dna,direction='in')
    check('Outbound forest does not transform inbound packet',len(parts)==1 and content(parts[0])==payload,
          {'direction':'in','outgoing_packets':len(parts)})
    _,parts=run('')
    check('Empty strategy is packet passthrough',len(parts)==1 and content(parts[0])==payload,
          {'outgoing_packets':len(parts)})
    _,parts=run('[TCP:flags:PA]-duplicate-|')
    check('Duplicate action branches into two copies',len(parts)==2 and all(content(p)==payload for p in parts),
          {'outgoing_packets':len(parts)})
    _,parts=run('[TCP:flags:PA]-drop-|')
    check('Drop action produces no output packets',len(parts)==0,{'outgoing_packets':len(parts)})
    _,parts=run('[TCP:flags:PA]-tamper{IP:ttl:replace:42}-|')
    check('Tamper changes selected header while preserving payload',
          len(parts)==1 and parts[0].packet[IP].ttl==42 and content(parts[0])==payload,
          {'ttl':parts[0].packet[IP].ttl})

    symbols=[('parser',actions.utils.parse),('trigger',actions.trigger.Trigger.is_applicable),
             ('strategy',actions.strategy.Strategy.act_on_packet),
             ('forest',actions.strategy.Strategy.run_on_packet),
             ('action_tree',actions.tree.ActionTree.run),
             ('tcp_segmentation',actions.fragment.FragmentAction.tcp_segment),
             ('mutation',actions.strategy.Strategy.mutate),
             ('crossover',actions.strategy.mate)]
    code_map=[]
    for label,obj in symbols:
        source=Path(inspect.getsourcefile(obj)).resolve()
        code_map.append(dict(component=label,file=os.path.relpath(str(source),str(root)),
            symbol=obj.__qualname__,line=inspect.getsourcelines(obj)[1],
            file_sha256=hashlib.sha256(source.read_bytes()).hexdigest()))
    # Static symbol map for search/engine/evaluation: 
    static={
        'evolve.py':['genetic_solve','run_collection_phase','initialize_population',
                     'mutation_crossover','fitness_function','selection_tournament','add_to_hof','eval_only'],
        'engine.py':['handle_packet','out_callback','in_callback'],
        'evaluator.py':['run_test','create_test_environment'],
    }
    import ast
    for relative,names in static.items():
        path=root/relative;tree=ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in names:
                code_map.append(dict(component='static_reference_only',file=relative,
                    symbol=node.name,line=node.lineno,file_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    try:commit=subprocess.check_output(['git','rev-parse','HEAD'],stderr=subprocess.DEVNULL).decode().strip()
    except (OSError,subprocess.CalledProcessError):commit='unavailable'
    report=dict(scope='Offline synthetic-packet walkthrough; original Geneva functions invoked',
        expected_upstream_commit='61a4a5104641ddbba6dd0526013e85a5be875203',
        actual_commit=commit,python=sys.version.split()[0],checks=results,source_map=code_map,
        genetic_search_executed=False,network_packets_sent=False,
        action_discovery='Original ACTION_CACHE prepopulated with four primitive classes to avoid TraceAction raw-socket construction',
        note='Written explanation and this code illustrate implementation understanding; personal mastery must be demonstrated by the applicant.')
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2)+'\n')
    print('Checks passed: %d/%d' % (len(results),len(results)))
    print('Saved: '+str(output))

if __name__=='__main__':main()
