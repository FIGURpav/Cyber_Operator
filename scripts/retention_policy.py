"""Administrative retention holds and classification; never purge a workspace."""
import argparse
import json
import re
import sys
from datetime import timedelta
from pathlib import Path

if __package__:
    from . import assessment_journal as journal
    from . import engagement_config as config
else:
    import assessment_journal as journal
    import engagement_config as config


def status(root):
    loaded=config.load(Path(root))
    if loaded is None:
        return {'classification':'legacy-unspecified','retention_days':None,'review_due':None,'holds':[],'automatic_purge':False}
    definition=loaded['definition']
    current={}
    for event in journal.load(root):
        if event['entity_kind']!='retention':
            continue
        value=event['data']
        config._keys(value,{'target','hold'},'retention record')
        if type(value['hold']) is not bool or not isinstance(value['target'],str) or (value['target']!='*' and not re.fullmatch(r'TXN-[0-9a-f]{32}',value['target'])):
            raise ValueError('invalid retention hold record')
        source=next(item['definition'] for item in loaded['events'] if item['definition_sha256']==event['configuration']['sha256'] and item['event'] in {'created','approved'})
        if event['actor']!=source['reviewer_id']:
            raise ValueError('retention action is not from the configured reviewer')
        current[value['target']]=value['hold']
    end=definition['ends_at']
    due=config._stamp(config._moment(end)+timedelta(days=definition['retention_days'])) if end else None
    return {'classification':definition['classification'],'retention_days':definition['retention_days'],
            'review_due':due,'holds':sorted(key for key,held in current.items() if held),'automatic_purge':False}


def require_clear(root,identifier='*'):
    held=status(root)['holds']
    if '*' in held or identifier in held or (identifier=='*' and held):
        raise ValueError('retention hold blocks cleanup; record an explicit reviewer release first')


def change(root,target,hold,*,actor,**kwargs):
    definition=config.load(Path(root))
    if not definition or actor!=definition['definition']['reviewer_id']:
        raise ValueError('retention changes require the configured reviewer')
    if type(hold) is not bool or not isinstance(target,str) or (target!='*' and not re.fullmatch(r'TXN-[0-9a-f]{32}',target)):
        raise ValueError('hold target must be * or an exact transaction ID')
    status(root)
    return journal.write(root,'retention',{'target':target,'hold':hold},actor=actor,**kwargs)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('status','hold','release'))
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--target',default='*')
    parser.add_argument('--actor')
    parser.add_argument('--reason')
    parser.add_argument('--expected-revision',type=int)
    parser.add_argument('--expected-event',type=int)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args(argv)
    try:
        result=status(args.workspace) if args.command=='status' else change(args.workspace,args.target,args.command=='hold',
            actor=args.actor,reason=args.reason,expected_revision=args.expected_revision,expected_event=args.expected_event,apply=args.apply)
        print(json.dumps(result,indent=2))
        return 0
    except (OSError,ValueError,RuntimeError) as exc:
        print(f'error: {exc}',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
