"""Record supplied activity once; never execute a command or contact a target."""
from __future__ import annotations

import argparse
import copy
import json
import sys
from datetime import timedelta
from pathlib import Path

if __package__:
    from . import assessment_journal as journal
    from . import assessment_model as model
    from . import engagement_config as config
    from . import (
        execution_provenance,
        log_attempt,
        log_observation,
        operational_trace,
        report_contract,
        structured_state,
        workspace_transaction,
    )
else:
    import assessment_journal as journal
    import assessment_model as model
    import engagement_config as config
    import execution_provenance
    import log_attempt
    import log_observation
    import operational_trace
    import report_contract
    import structured_state
    import workspace_transaction

DEFAULTS = {'summary':'','result':'','host_ids':[],'asset_ids':[],'objective_ids':[],
            'evidence_ids':[],'finding_ids':[],'change_ids':[],'claim_ids':[],'run_ids':[],
            'attempt':None,'task':None,'finding':None,'observation_ids':[],
            'local_artifact_ids':[],'local_artifact':None}


def prepare(root, value, *, actor, reason, key, expected_revision, expected_event, now=None):
    root=Path(root).absolute()
    moment=config._moment(config._stamp(now))
    config._text(key,'idempotency key',160)
    if not isinstance(value,dict) or not set(value)<=set(DEFAULTS):
        raise ValueError('activity contains unsupported fields')
    value={**copy.deepcopy(DEFAULTS),**copy.deepcopy(value)}
    request_hash=config.digest({'input':value,'actor':actor,'reason':reason})
    compatible_hashes={request_hash}
    if not value['observation_ids'] and not value['local_artifact_ids'] and value['local_artifact'] is None:
        previous={key:item for key,item in value.items() if key not in {'observation_ids','local_artifact_ids','local_artifact'}}
        compatible_hashes.add(config.digest({'input':previous,'actor':actor,'reason':reason}))
    existing=[event for event in journal.load(root) if event['entity_kind']=='activity' and event['data'].get('idempotency_key')==key]
    if existing:
        if existing[0]['data']['request_sha256'] not in compatible_hashes:
            raise ValueError('idempotency key already identifies a different request')
        return {'mode':'EXISTING','record':existing[0],'operations':[]}
    config._text(value['summary'],'activity summary',240)
    config._text(value['result'],'activity result',8192)
    if len(value['result'].encode())>8192:
        raise ValueError('activity result exceeds 8192 bytes; reference captured evidence instead')
    if not isinstance(value['host_ids'],list):
        raise ValueError('host_ids must be a list')  # noqa: TRY004 -- public validation contract
    hosts=structured_state._host_ids(root,value['host_ids']) if value['host_ids'] else []
    value['host_ids']=hosts
    known=model.states(root)
    evidence=report_contract._evidence_index(root)
    for field,kind in (('asset_ids','asset'),('objective_ids','objective'),('finding_ids','finding')):
        model.references(value[field],field,{key:item for key,item in known.items() if item['entity_kind']==kind})
    model.references(value['evidence_ids'],'evidence_ids',evidence)
    observations=log_observation._read_existing_records(root/'observations.jsonl') if (root/'observations.jsonl').exists() else []
    model.references(value['observation_ids'],'observation_ids',{item['observation_id']:item for item in observations})
    artifacts=structured_state.local_artifact_states(root)
    model.references(value['local_artifact_ids'],'local_artifact_ids',artifacts)
    if value['change_ids']:
        model.references(value['change_ids'],'change_ids',{item['change_id']:item for item in operational_trace.load_changes(root)})
    if value['claim_ids']:
        model.references(value['claim_ids'],'claim_ids',execution_provenance.load_claims(root))
    if value['run_ids']:
        model.references(value['run_ids'],'run_ids',execution_provenance.load_runs(root))
    for field in ('change_ids','claim_ids','run_ids'):
        if not isinstance(value[field],list):
            raise ValueError(f'{field} must be a list')  # noqa: TRY004 -- public validation contract
    report_contract.reject_secrets(root,{'value':value,'actor':actor,'reason':reason,'key':key})
    operations=[]
    if value['local_artifact'] is not None:
        config._keys(value['local_artifact'],{'path','artifact_class'},'local artifact options')
        artifact=structured_state.register_local_artifact(root,**value['local_artifact'],purpose=value['summary'],host_ids=hosts,now=moment)
        if any(item['relative_path']==artifact['relative_path'] and item['state'] not in {'disposed','missing'} for item in artifacts.values()):
            raise ValueError('local artifact is already registered; link its ID instead')
        value['local_artifact_ids'].append(artifact['local_artifact_id'])
        operations.append((structured_state.LOCAL_ARTIFACT_LEDGER,artifact))
    attempt_id=None
    task_id=None
    if value['attempt'] is not None:
        config._keys(value['attempt'],{'status','next_step'},'attempt options')
        if len(hosts)!=1:
            raise ValueError('an attempt requires exactly one host')
        options=value['attempt']
        if options['status'] not in log_attempt.VALID_STATUSES:
            raise ValueError('unsupported attempt status')
        config._text(options['next_step'],'next step',240)
        existing_attempts=operational_trace._attempt_index(root)
        attempt_id=log_attempt.build_attempt_id(moment)
        while attempt_id in existing_attempts:
            moment+=timedelta(microseconds=1)
            attempt_id=log_attempt.build_attempt_id(moment)
        attempt=log_attempt.build_record(attempt_id,moment,hosts[0],value['summary'],options['status'],
                                        value['result'].encode(),value['evidence_ids'],options['next_step'])
        operations.append(('attempts.jsonl',attempt))
    if value['task'] is not None:
        config._keys(value['task'],{'kind','external_ref','state'},'task options')
        task=structured_state.create_work_item(root,**value['task'],host_ids=hosts,summary=value['summary'],
                                               references=value['evidence_ids']+value['claim_ids'],owner=actor,now=moment)
        if attempt_id:
            task['references']=sorted(task['references']+[attempt_id])
        task_id=task['work_item_id']
        operations.append((structured_state.WORK_ITEM_LEDGER,task))
    finding=None
    if value['finding'] is not None:
        if not isinstance(value['finding'],dict):
            raise ValueError('finding options must be an object')
        finding_input={'title':value['summary'],'asset_ids':value['asset_ids'],'objective_ids':value['objective_ids'],
                       'evidence_ids':value['evidence_ids'],**value['finding']}
        finding=model.change(root,'finding',finding_input,actor=actor,reason=reason,
                             expected_revision=expected_revision,expected_event=expected_event,now=moment)['record']
        value['finding_ids'].append(finding['entity_id'])
        operations.append((journal.LEDGER,finding))
    data={key:item for key,item in value.items() if key not in {'attempt','task','finding','local_artifact'}}
    data.update(idempotency_key=key,request_sha256=request_hash,attempt_id=attempt_id,task_id=task_id)
    event=journal.write(root,'activity',data,actor=actor,reason=reason,expected_revision=expected_revision,
                        expected_event=expected_event,now=moment)['record']
    if finding:
        event['sequence']+=1
        event['previous_sha256']=finding['event_sha256']
        event['event_sha256']=config.digest({key:item for key,item in event.items() if key!='event_sha256'})
    operations.append((journal.LEDGER,event))
    for name in {name for name,_ in operations}:
        current=(root/name).stat().st_size if (root/name).exists() else 0
        if current+sum(len(config.encoded(item)) for path,item in operations if path==name)>journal.MAX_BYTES:
            raise ValueError('activity ledger size limit reached')
    return {'mode':'PREVIEW','record':event,'operations':operations}


def record(root,value,*,apply=False,**kwargs):
    root=Path(root).absolute()
    if not apply:
        return prepare(root,value,**kwargs)
    with workspace_transaction.write_guard(root):
        result=prepare(root,value,**kwargs)
        if result['mode']=='EXISTING':
            return result
        transaction=workspace_transaction.Transaction(root,'assessment-activity')
        for path,event in result['operations']:
            transaction.add('append',root/path,config.encoded(event))
        result['transaction_id']=transaction.commit()
        result['mode']='APPLY'
        return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--idempotency-key',required=True)
    parser.add_argument('--actor',required=True)
    parser.add_argument('--reason',required=True)
    parser.add_argument('--expected-revision',type=int,required=True)
    parser.add_argument('--expected-event',type=int,required=True)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args(argv)
    try:
        result=record(args.workspace,config.read_input(args.input),actor=args.actor,reason=args.reason,
                      key=args.idempotency_key,expected_revision=args.expected_revision,expected_event=args.expected_event,apply=args.apply)
        print(json.dumps(result,indent=2))
        return 0
    except (ValueError,RuntimeError,OSError) as exc:
        print(f'error: {exc}',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
