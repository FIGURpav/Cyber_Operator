"""Explicit AI session metadata; no automatic conversation capture."""
import argparse
import json
import sys
from pathlib import Path

if __package__:
    from . import assessment_journal as journal
    from . import assessment_model as model
    from . import engagement_config as config
    from . import report_contract, workspace_transaction
else:
    import assessment_journal as journal
    import assessment_model as model
    import engagement_config as config
    import report_contract
    import workspace_transaction


def record(root,value,*,apply=False,**kwargs):
    root=Path(root).absolute()
    if apply:
        with workspace_transaction.write_guard(root):
            result=record(root,value,**kwargs)
            return journal.write(root,'ai-session',result['record']['data'],apply=True,**kwargs)
    config._keys(value,{'provider','model','session_label','purpose','query_ids','response_evidence_ids','decision_ids'},'AI session metadata')
    for field in ('provider','model','session_label','purpose'):
        config._text(value[field],field,1024)
    evidence=report_contract._evidence_index(root)
    model.references(value['response_evidence_ids'],'response evidence',evidence)
    model.references(value['decision_ids'],'decision IDs',journal.states(root,'decision'))
    if not isinstance(value['query_ids'],list) or len(value['query_ids'])>100 or len(set(value['query_ids']))!=len(value['query_ids']):
        raise ValueError('query_ids must be a bounded unique list')
    for identifier in value['query_ids']:
        if not isinstance(identifier,str) or not report_contract.QUERY_ID_RE.fullmatch(identifier):
            raise ValueError('malformed query ID')
        path=workspace_transaction.safe_path(root,f'queries/{identifier}.json')
        query=json.loads(workspace_transaction.read_file(path,1024*1024))
        if query.get('query_id')!=identifier:
            raise ValueError('query identity mismatch')
    return journal.write(root,'ai-session',value,**kwargs)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--actor',required=True)
    parser.add_argument('--reason',required=True)
    parser.add_argument('--expected-revision',type=int,required=True)
    parser.add_argument('--expected-event',type=int,required=True)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args(argv)
    try:
        print(json.dumps(record(args.workspace,config.read_input(args.input),actor=args.actor,reason=args.reason,
                                expected_revision=args.expected_revision,expected_event=args.expected_event,apply=args.apply),indent=2))
        return 0
    except (OSError,ValueError,RuntimeError) as exc:
        print(f'error: {exc}',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
