"""Render documented relationships and retained operational paths; no planning."""
import argparse
import json
import re
import sys
from html import escape
from pathlib import Path

if __package__:
    from . import (
        assessment_model,
        operational_trace,
        report_contract,
        workspace_transaction,
    )
else:
    import assessment_model
    import operational_trace
    import report_contract
    import workspace_transaction


def graph(root):
    states = assessment_model.states(root)
    nodes = {}
    edges = []
    for key,event in sorted(states.items()):
        kind = event['entity_kind']
        data = event['data']
        if kind in {'asset','finding'}:
            nodes[key] = data['name'] if kind=='asset' else data['title']
        elif kind=='relationship':
            edges.append({'id':key,'source':data['source_id'],'destination':data['destination_id'],
                          'label':data['label'],'state':data['state'],'evidence_ids':data['evidence_ids']})
    for record in operational_trace.load_attack_paths(root):
        source = record['source_host_id']+':'+record['source_identity']
        destination = record['destination_host_id']+':'+record['destination_identity']
        nodes[source] = source
        nodes[destination] = destination
        edges.append({'id':record['path_event_id'],'source':source,'destination':destination,
                      'label':record['transition']+' / '+record['status'],
                      'state':'observed' if record['status']=='success' else 'rejected' if record['status']=='blocked' else 'inferred',
                      'evidence_ids':record['evidence_ids']})
    if len(nodes)>100 or len(edges)>200:
        raise ValueError('graph exceeds the readable export limit; partition the reviewed records')
    result={'nodes':nodes,'edges':sorted(edges,key=lambda item:item['id'])}
    report_contract.reject_secrets(root,result)
    return result


def svg(value):
    nodes=sorted(value['nodes'])
    positions={key:(40+(index%2)*600,100+(index//2)*150) for index,key in enumerate(nodes)}
    height=max(330,230+((len(nodes)+1)//2)*150+len(value['edges'])*24)
    out=[f'<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="{height}" viewBox="0 0 1200 {height}" role="img" aria-label="Documented assessment relationships">',
         '<title>Documented assessment relationships</title><rect width="1200" height="100%" fill="#f7f9fc"/>',
         '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#546a83"/></marker></defs>',
         '<g font-family="sans-serif" fill="#203047"><text x="40" y="40" font-size="25">Documented relationships and paths</text>',
         '<text x="40" y="68" font-size="14">Solid: observed · Dashed: inferred · Dotted: rejected. Edges describe retained records.</text>']
    for index,edge in enumerate(value['edges'],1):
        x1,y1=positions[edge['source']]
        x2,y2=positions[edge['destination']]
        dash={'observed':'','inferred':'8 5','rejected':'2 5'}[edge['state']]
        out.append(f'<path d="M {x1+245} {y1+62} L {x2+245} {y2}" fill="none" stroke="#546a83" stroke-width="2" stroke-dasharray="{dash}" marker-end="url(#arrow)"><title>{escape(edge["label"])}</title></path>')
        out.append(f'<text x="{(x1+x2)//2+250}" y="{(y1+y2)//2+32}" font-size="13">{index}</text>')
    for index,key in enumerate(nodes):
        x,y=positions[key]
        label=value['nodes'][key]
        out.append(f'<g id="node-{index}"><title>{escape(label)} — {escape(key)}</title><rect x="{x}" y="{y}" width="490" height="62" rx="6" fill="white" stroke="#9eb4cc"/><text x="{x+12}" y="{y+26}" font-size="16">{escape(label[:53])}</text><text x="{x+12}" y="{y+47}" font-size="10">{escape(key[:74])}</text></g>')
    y=130+((len(nodes)+1)//2)*150
    out.append(f'<text x="40" y="{y}" font-size="18">Evidence references</text>')
    for index,edge in enumerate(value['edges'],1):
        line=f'{index}. {edge["state"]}: {edge["label"]} | {edge["id"]} | '+(', '.join(edge['evidence_ids']) or 'No evidence attached')
        out.append(f'<text x="40" y="{y+index*24}" font-size="11"><title>{escape(line)}</title>{escape(line[:165])}</text>')
    out.append('</g></svg>')
    return '\n'.join(out)


def export(root,output,*,apply=False):
    root=Path(root).absolute()
    output=Path(output)
    if output.is_absolute() or len(output.parts)!=2 or output.parts[0]!='report' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*\.svg',output.name):
        raise ValueError('graph output must be a new report/NAME.svg inside the workspace')
    if apply:
        with workspace_transaction.write_guard(root):
            result=export(root,output)
            transaction=workspace_transaction.Transaction(root,'assessment-report')
            transaction.add('create',root/output,result.pop('_svg').encode())
            transaction.commit()
            result['mode']='APPLY'
            return result
    target=workspace_transaction.safe_path(root,output.as_posix())
    if target.exists():
        raise ValueError('graph output exists; select a new filename')
    value=graph(root)
    result=svg(value)
    report_contract.reject_secrets(root,{'svg':result})
    return {'mode':'PREVIEW','output':output.as_posix(),'nodes':len(value['nodes']),'edges':len(value['edges']),
            'content_sha256':workspace_transaction.digest(result.encode()),'_svg':result}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--output',default='report/attack_path.svg')
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args(argv)
    try:
        value=export(args.workspace,args.output,apply=args.apply)
        print(json.dumps({key:item for key,item in value.items() if not key.startswith('_')},indent=2))
        return 0
    except (OSError,ValueError,RuntimeError) as exc:
        print(f'error: {exc}',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
