"""Optional reviewed plaintext export to a private local workspace file."""
import argparse
import json
import sys
from pathlib import Path

if __package__:
    from . import artifact_io, assessment_decisions, report_contract
    from . import assessment_journal as journal
    from . import engagement_config as config
    from . import workspace_transaction as tx
else:
    import artifact_io
    import assessment_decisions
    import assessment_journal as journal
    import engagement_config as config
    import report_contract
    import workspace_transaction as tx


def plan(root,ids,decision_id,*,actor,reason,audience,retention_days,expected_revision,expected_event,now=None):
    root=Path(root).absolute()
    definition=config.load(root)['definition']
    decision=assessment_decisions.decision_states(root).get(decision_id)
    moment=config._moment(config._stamp(now))
    instance,epoch,_,_=config._environment(root)
    if (not decision or decision['data']['status']!='approved'
            or decision['data']['proposal']['purpose']!='sensitive-export'
            or decision['configuration']['sha256']!=config.digest(definition)
            or decision['instance_id']!=instance or decision['lifecycle_epoch']!=epoch
            or config.status(root,now=moment)['status']!='active'
            or not config._moment(decision['data']['proposal']['starts_at'])<=moment<config._moment(decision['data']['proposal']['ends_at'])):
        raise ValueError('sensitive export requires a current reviewed disclosure decision')
    if actor!=definition['reviewer_id']:
        raise ValueError('exact sensitive export selection requires the configured reviewer')
    config._text(audience,'sensitive export audience',512)
    if type(retention_days) is not int or not 1<=retention_days<=definition['retention_days']:
        raise ValueError('export retention must remain within assessment retention')
    if not isinstance(ids,list) or not ids or len(ids)>100 or len(set(ids))!=len(ids):
        raise ValueError('select a bounded unique list of credential IDs')
    ids=sorted(ids)
    available=report_contract._credential_index(root)
    if any(identifier not in available or available[identifier]['host_id'] not in decision['data']['proposal']['host_ids'] for identifier in ids):
        raise ValueError('selected credential is unavailable or outside the reviewed host scope')
    hashes={identifier:config.digest(available[identifier]) for identifier in sorted(ids)}
    data={'credential_ids':sorted(ids),'decision_id':decision_id,'credential_sha256':hashes,
          'destination':None,'plaintext':True,'remote_revocation':False,'audience':audience,'retention_days':retention_days}
    event=journal.write(root,'disclosure',data,actor=actor,reason=reason,
                        expected_revision=expected_revision,expected_event=expected_event,now=moment)['record']
    # A deterministic destination makes preview/apply and duplicate refusal explicit.
    data['destination']='private/vault/exports/EXP-'+config.digest({'ids':ids,'decision':decision_id,'event':expected_event,'hashes':hashes})[:32]+'.json'
    result={'schema_version':'1.0','workspace':str(root),'created_at_utc':config._stamp(moment),'data':data,
            'actor':actor,'reason':reason,'expected_revision':expected_revision,'expected_event':expected_event,
            'configuration':event['configuration']}
    result['plan_sha256']=config.digest(result)
    return result


def apply(root,reviewed,*,now=None):
    root=Path(root).absolute()
    with tx.write_guard(root):
        current=plan(root,reviewed['data']['credential_ids'],reviewed['data']['decision_id'],actor=reviewed['actor'],
                     reason=reviewed['reason'],audience=reviewed['data']['audience'],retention_days=reviewed['data']['retention_days'],
                     expected_revision=reviewed['expected_revision'],expected_event=reviewed['expected_event'],now=now)
        # Current time must still be authorized, but it does not change the reviewed selection.
        current['created_at_utc']=reviewed['created_at_utc']
        current['plan_sha256']=config.digest({key:value for key,value in current.items() if key!='plan_sha256'})
        if current!=reviewed:
            raise ValueError('sensitive export plan changed; review a fresh preview')
        available=report_contract._credential_index(root)
        payload={'classification':config.load(root)['definition']['classification'],'plaintext_secrets':True,
                 'credentials':[available[identifier] for identifier in reviewed['data']['credential_ids']]}
        for relative in ('private','private/vault','private/vault/exports'):
            tx._private_directory(tx.safe_path(root,relative))
        event=journal.write(root,'disclosure',reviewed['data'],actor=reviewed['actor'],reason=reviewed['reason'],
                            expected_revision=reviewed['expected_revision'],expected_event=reviewed['expected_event'],now=now)['record']
        transaction=tx.Transaction(root,'vault-disclosure')
        transaction.add('create',tx.safe_path(root,reviewed['data']['destination']),config.encoded(payload))
        transaction.add('append',root/journal.LEDGER,config.encoded(event))
        return {'transaction_id':transaction.commit(),'destination':reviewed['data']['destination'],
                'credential_ids':reviewed['data']['credential_ids'],'disclosure_id':event['entity_id']}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('preview','apply'))
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--plan-file',type=Path,required=True)
    parser.add_argument('--credential-id',action='append',default=[])
    parser.add_argument('--decision-id')
    parser.add_argument('--actor')
    parser.add_argument('--reason')
    parser.add_argument('--audience')
    parser.add_argument('--retention-days',type=int)
    parser.add_argument('--expected-revision',type=int)
    parser.add_argument('--expected-event',type=int)
    args=parser.parse_args(argv)
    try:
        if args.command=='preview':
            result=plan(args.workspace,args.credential_id,args.decision_id,actor=args.actor,reason=args.reason,
                        audience=args.audience,retention_days=args.retention_days,expected_revision=args.expected_revision,expected_event=args.expected_event)
            artifact_io.publish_file(args.plan_file,config.encoded(result))
        else:
            result=apply(args.workspace,config.read_input(args.plan_file))
        print(json.dumps(result,indent=2))
        return 0
    except (OSError,ValueError,RuntimeError,KeyError,TypeError):
        print('error: sensitive export requires an unchanged reviewed plan, current decision and available private values',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
