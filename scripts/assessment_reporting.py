"""Configuration-bound findings reports with explicit coverage and limitations."""
from __future__ import annotations

import argparse
import json
import re
import sys
from html import escape
from pathlib import Path

if __package__:
    from . import assessment_journal as journal
    from . import assessment_model as model
    from . import (
        configuration_report,
        report_contract,
        token_lifecycle,
        workspace_transaction,
    )
    from . import engagement_config as config
else:
    import assessment_journal as journal
    import assessment_model as model
    import configuration_report
    import engagement_config as config
    import report_contract
    import token_lifecycle
    import workspace_transaction

FIELDS = {'schema_version','report_id','created_at_utc','configuration','assessment','journal',
          'assets','objectives','findings','relationships','limitations','snapshot_sha256'}
ASSESSMENT_FIELDS = ('name','team_id','operator_id','reviewer_id','scope_reference','in_scope','excluded',
                     'starts_at','ends_at','objectives','maximum_impact','artifact_handling','classification')
KINDS = {'assets':'asset','objectives':'objective','findings':'finding','relationships':'relationship'}


def _view(event):
    return {'id':event['entity_id'],'revision':event['entity_revision'],'event_sequence':event['sequence'],
            'event_sha256':event['event_sha256'],'data':event['data']}


def build(root, *, limitations=None, now=None):
    root = Path(root).absolute()
    loaded = config.load(root)
    if loaded is None:
        raise ValueError('findings reports require a managed workspace')
    approval = next((event for event in reversed(loaded['events']) if event['event']=='approved'),None)
    if approval is None:
        raise ValueError('report snapshot requires a reviewed configuration')
    definition = approval['definition']
    reference = {'engagement_id':definition['engagement_id'],'revision':definition['revision'],
                 'sha256':config.digest(definition),'approval_event':approval['sequence']}
    if not configuration_report.is_current(root,{'configuration':reference}):
        raise ValueError('report snapshot requires the current configuration review')
    records = journal.load(root)
    states = model.states(root)
    stamp = config._stamp(now)
    value = {'schema_version':'3.0','report_id':'RPT-'+config._moment(stamp).strftime('%Y%m%dT%H%M%S%fZ'),
             'created_at_utc':stamp,'configuration':reference,
             'assessment':{key:definition[key] for key in ASSESSMENT_FIELDS},
             'journal':{'sequence':len(records),'sha256':records[-1]['event_sha256'] if records else None},
             'limitations':limitations or []}
    for field,kind in KINDS.items():
        value[field] = [_view(event) for _,event in sorted(states.items()) if event['entity_kind']==kind]
    value['snapshot_sha256'] = config.digest(value)
    validate(root,value)
    return value


def validate(root,value):
    config._keys(value,FIELDS,'findings report snapshot')
    if value['schema_version']!='3.0':
        raise ValueError('unsupported findings report schema')
    config._moment(value['created_at_utc'])
    if value['report_id'] != 'RPT-'+config._moment(value['created_at_utc']).strftime('%Y%m%dT%H%M%S%fZ'):
        raise ValueError('report identifier differs from creation time')
    if value['snapshot_sha256'] != config.digest({key:item for key,item in value.items() if key!='snapshot_sha256'}):
        raise ValueError('report snapshot hash mismatch')
    definition,_ = configuration_report.reviewed_snapshot(root,value['configuration'])
    if value['assessment'] != {key:definition[key] for key in ASSESSMENT_FIELDS}:
        raise ValueError('report assessment facts differ from the reviewed configuration')
    config._keys(value['journal'],{'sequence','sha256'},'report journal reference')
    records = journal.load(root)
    count = value['journal']['sequence']
    if type(count) is not int or not 0<=count<=len(records):
        raise ValueError('report journal sequence is unavailable')
    if value['journal']['sha256'] != (records[count-1]['event_sha256'] if count else None):
        raise ValueError('report journal reference differs from history')
    model.states(root)
    states = {event['entity_id']:event for event in records[:count] if event['entity_kind'] in model.DEFAULTS}
    for field,kind in KINDS.items():
        expected = [_view(event) for _,event in sorted(states.items()) if event['entity_kind']==kind]
        if value[field] != expected:
            raise ValueError(f'report {field} differ from retained record revisions')
    config._strings(value['limitations'],'report limitations')
    report_contract.reject_secrets(root,value)
    return value


def content_blockers(value,evidence):
    blockers = []
    if not value['assets']:
        blockers.append('assets:missing')
    covered = {item['data']['title'] for item in value['objectives']}
    for title in value['assessment']['objectives']:
        if title not in covered:
            blockers.append('objective:unrecorded:' + title)
    for item in value['assets']:
        if not set(item['data']['scope_assets']) <= set(value['assessment']['in_scope']):
            blockers.append(item['id']+':scope-requires-review')
    for item in value['objectives']:
        data = item['data']
        if data['title'] not in value['assessment']['objectives']:
            blockers.append(item['id']+':objective-no-longer-in-configuration')
        if data['status'] in {'planned','in-progress'}:
            blockers.append(item['id']+':coverage-unresolved')
        if data['review'] is None:
            blockers.append(item['id']+':review-required')
    for item in value['findings']:
        data = item['data']
        if data['review'] is None:
            blockers.append(item['id']+':review-required')
        if data['confidence']=='confirmed' and (not data['impact'] or not data['recommendation']):
            blockers.append(item['id']+':impact-or-remediation-missing')
        if data['evidence_policy']=='screenshot' and not any(str(evidence[eid].get('artifact_path','')).lower().endswith('.png') for eid in data['evidence_ids']):
            blockers.append(item['id']+':requested-screenshot-missing')
        if data['risk_acceptance'] and config._moment(data['risk_acceptance']['expires_at']) <= config._moment(value['created_at_utc']):
            blockers.append(item['id']+':risk-acceptance-expired')
    return blockers


def readiness(root, value=None):
    value = value or build(root)
    validate(root,value)
    blockers = content_blockers(value,report_contract._evidence_index(root))
    if not configuration_report.is_current(root,value):
        blockers.append('configuration:report-snapshot-requires-refresh-and-review')
    if value['journal']['sequence'] != len(journal.load(root)):
        blockers.append('records:report-snapshot-requires-refresh')
    blockers.extend('token:'+item for item in token_lifecycle.closure_readiness(root).blockers)
    return {'ready':not blockers,'blockers':blockers,'objectives':len(value['objectives']),
            'findings':len(value['findings']),'query_appendix':'optional','screenshots':'finding-specific'}


def render(value,checks):
    def e(item):
        return escape(str(item))
    def listing(items):
        return '<ul>'+''.join('<li>'+e(item)+'</li>' for item in items)+'</ul>'
    assessment = value['assessment']
    out = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width,initial-scale=1">',
           '<meta name="cyber-snapshot-sha256" content="'+e(value['snapshot_sha256'])+'">',
           '<title>'+e(assessment['name'])+' — Assessment report</title>',
           '<style>body{font:16px/1.6 system-ui,sans-serif;color:#203047;max-width:1000px;margin:40px auto;padding:0 24px}h1,h2{color:#164e82}table{border-collapse:collapse;width:100%;font-size:14px}td,th{border:1px solid #ccd7e4;text-align:left;padding:10px;vertical-align:top}th{background:#eef3f9}.finding{border-top:2px solid #ccd7e4;padding-top:16px;margin:32px 0}code{overflow-wrap:anywhere}.draft{background:#fff3d6;padding:12px}pre{white-space:pre-wrap}</style></head><body>',
           '<h1>'+e(assessment['name'])+'</h1>',
           '<p>Team: '+e(assessment['team_id'])+' · Generated: '+e(value['created_at_utc'])+'</p>',
           '<p>Configuration revision '+e(value['configuration']['revision'])+'; report '+e(value['report_id'])+'</p>']
    if not checks['ready']:
        out.append('<div class="draft"><strong>Draft — unresolved report checks</strong>'+listing(checks['blockers'])+'</div>')
    out.extend(['<h2>Scope</h2>',listing(assessment['in_scope']),'<p>External scope reference: '+e(assessment['scope_reference'] or 'No external document; local reviewed configuration')+'</p>',
                '<p>Assessment window: '+e(assessment['starts_at'])+' — '+e(assessment['ends_at'])+'</p>',
                '<h2>Exclusions and limitations</h2>',listing(assessment['excluded']+value['limitations']),
                '<h2>Objective coverage</h2><table><tr><th>Objective</th><th>Outcome</th><th>Limitations and evidence</th></tr>'])
    for item in value['objectives']:
        data = item['data']
        out.append('<tr><td>'+e(data['title'])+'</td><td>'+e(data['status'])+'</td><td>'+e(data['limitation'] or '')+'<br>'+e(', '.join(data['evidence_ids']+data['finding_ids']))+'</td></tr>')
    out.append('</table><h2>Findings and review outcomes</h2>')
    if not value['findings']:
        out.append('<p>No finding records are included. This does not establish that the application has no vulnerabilities; see objective coverage.</p>')
    for item in value['findings']:
        data = item['data']
        out.extend(['<article class="finding" id="'+e(item['id'])+'"><h3>'+e(data['title'])+'</h3>',
                    '<p>'+e(data['severity'])+' · '+e(data['confidence'])+' · Remediation: '+e(data['remediation_status'])+' · Retest: '+e(data['retest_status'])+'</p>',
                    '<p>'+e(data['impact'])+'</p><p><strong>Recommendation:</strong> '+e(data['recommendation'])+'</p>',
                    '<p>Assets: '+e(', '.join(data['asset_ids']))+'<br>Evidence: '+e(', '.join(data['evidence_ids']))+'</p>',
                    '<p>Record '+e(item['id'])+' · revision '+e(item['revision'])+'</p></article>'])
    out.extend(['<h2>Traceability</h2><p>Snapshot SHA-256: <code>'+e(value['snapshot_sha256'])+'</code></p>',
                '<p>Assessment journal sequence: '+e(value['journal']['sequence'])+'. Secret values are not included in this report.</p></body></html>'])
    return '\n'.join(out)


def publish(root,output,*,limitations=None,apply=False,now=None):
    root = Path(root).absolute()
    output = Path(output)
    if output.is_absolute() or len(output.parts)!=2 or output.parts[0]!='report' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*\.html',output.name):
        raise ValueError('output must be a new report/NAME.html inside the workspace')
    if apply:
        with workspace_transaction.write_guard(root):
            result = publish(root,output,limitations=limitations,now=now)
            transaction = workspace_transaction.Transaction(root,'assessment-report')
            transaction.add('create',root/output, result.pop('_html').encode())
            transaction.add('create',(root/output).with_suffix('.json'),config.encoded(result.pop('_snapshot')))
            transaction.commit()
            result['mode']='APPLY'
            return result
    for path in (root/output,(root/output).with_suffix('.json')):
        workspace_transaction.safe_path(root,path.relative_to(root).as_posix())
        if path.exists():
            raise ValueError('report output already exists; use a new filename')
    value = build(root,limitations=limitations,now=now)
    checks = readiness(root,value)
    html = render(value,checks)
    report_contract.reject_secrets(root,{'report':html})
    return {'mode':'PREVIEW','output':output.as_posix(),'snapshot_sha256':value['snapshot_sha256'],
            'checks':checks,'_snapshot':value,'_html':html}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('build','readiness','snapshot'))
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--output',default='report/assessment-report.html')
    parser.add_argument('--limitation',action='append',default=[])
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args(argv)
    try:
        if args.command=='readiness':
            result=readiness(args.workspace)
        elif args.command=='snapshot':
            result=build(args.workspace,limitations=args.limitation)
        else:
            result=publish(args.workspace,args.output,limitations=args.limitation,apply=args.apply)
            result={key:value for key,value in result.items() if not key.startswith('_')}
        print(json.dumps(result,indent=2))
        return 0
    except (OSError,ValueError,RuntimeError) as exc:
        print(f'error: {exc}',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
