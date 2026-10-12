"""Versioned assets, objectives, findings and documented relationships."""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

if __package__:
    from . import assessment_journal as journal
    from . import engagement_config as config
    from . import host_identity, report_contract, workspace_transaction
else:
    import assessment_journal as journal
    import engagement_config as config
    import host_identity
    import report_contract
    import workspace_transaction

DEFAULTS = {
    'asset': {'kind':'application','name':'','locator':'','scope_assets':[], 'host_ids':[],
              'parent_ids':[],'status':'active','review':None},
    'objective': {'title':'','asset_ids':[],'status':'planned','evidence_ids':[],
                  'finding_ids':[],'limitation':None,'review':None},
    'finding': {'title':'','severity':'medium','confidence':'hypothesis','asset_ids':[],
                'objective_ids':[],'evidence_ids':[],'impact':'','recommendation':'',
                'remediation_status':'unplanned','retest_status':'not-tested','risk_acceptance':None,
                'evidence_policy':'sufficient','legacy_id':None,'review':None},
    'relationship': {'source_id':'','destination_id':'','label':'','state':'inferred',
                     'evidence_ids':[],'review':None},
}


def text(value, name, *, maximum=8192, empty=False):
    if (not isinstance(value,str) or len(value)>maximum or (not value.strip() and not empty)
            or any(ord(c)<32 and c not in '\n\t' for c in value)):
        raise ValueError(f'{name} must be bounded printable text')
    return value


def references(values, name, known, *, required=False):
    config._strings(values,name)
    if required and not values:
        raise ValueError(f'{name} must not be empty')
    if any(value not in known for value in values):
        raise ValueError(f'{name} contains an unknown reference')


def _within_scope(locator, scope):
    if locator == scope:
        return True
    first, second = urlsplit(locator), urlsplit(scope)
    if any(part in {'.','..'} for part in unquote(first.path).split('/')) or '\\' in unquote(first.path):
        return False
    try:
        if (first.scheme not in {'http','https'} or first.scheme != second.scheme
                or first.hostname != second.hostname or (first.port or (443 if first.scheme=='https' else 80)) != (second.port or (443 if second.scheme=='https' else 80))
                or first.username is not None or first.password is not None or first.fragment):
            return False
    except ValueError:
        return False
    prefix = second.path.rstrip('/')
    return not prefix or first.path == prefix or first.path.startswith(prefix + '/')


def validate_data(root,kind,data,definition,known,evidence,*,entity_id=None):
    config._keys(data,DEFAULTS[kind],kind)
    assets = {key for key,value in known.items() if value['entity_kind']=='asset'}
    objectives = {key for key,value in known.items() if value['entity_kind']=='objective'}
    findings = {key for key,value in known.items() if value['entity_kind']=='finding'}
    if kind == 'asset':
        text(data['name'],'asset name',maximum=512)
        text(data['locator'],'asset locator',maximum=2048)
        if data['kind'] not in {'application','service','endpoint','host','identity'} or data['status'] not in {'active','retired'}:
            raise ValueError('unsupported asset kind or state')
        references(data['scope_assets'],'scope_assets',definition['in_scope'],required=True)
        if not any(_within_scope(data['locator'],scope) for scope in data['scope_assets']):
            raise ValueError('asset locator is outside its explicit scope reference')
        if any(_within_scope(data['locator'],excluded) for excluded in definition['excluded']):
            raise ValueError('asset locator falls under an excluded scope reference')
        references(data['host_ids'],'host_ids',host_identity.known_host_ids(root))
        references(data['parent_ids'],'parent_ids',assets)
        pending = list(data['parent_ids'])
        visited = set()
        while pending:
            parent = pending.pop()
            if parent == entity_id:
                raise ValueError('asset parent relationship would create a cycle')
            if parent not in visited:
                visited.add(parent)
                pending.extend(known[parent]['data']['parent_ids'])
    elif kind == 'objective':
        text(data['title'],'objective title',maximum=1024)
        if data['title'] not in definition['objectives']:
            raise ValueError('objective must belong to the reviewed configuration')
        references(data['asset_ids'],'asset_ids',assets,required=True)
        references(data['evidence_ids'],'evidence_ids',evidence)
        references(data['finding_ids'],'finding_ids',findings)
        if data['status'] not in {'planned','in-progress','complete','partial','not-tested','not-applicable'}:
            raise ValueError('unsupported objective state')
        if data['status'] == 'complete' and not data['evidence_ids'] and not data['finding_ids']:
            raise ValueError('completed objectives require evidence or findings')
        if data['limitation'] is not None:
            text(data['limitation'],'objective limitation')
        if data['status'] in {'partial','not-tested','not-applicable'} and not data['limitation']:
            raise ValueError('incomplete or inapplicable objectives require an explicit limitation')
        if entity_id and any(entity_id not in known[identifier]['data']['objective_ids'] for identifier in data['finding_ids']):
            raise ValueError('objective finding reference has no reciprocal objective link')
    elif kind == 'finding':
        text(data['title'],'finding title',maximum=512)
        text(data['impact'],'finding impact',empty=True)
        text(data['recommendation'],'recommendation',empty=True)
        if data['severity'] not in {'informational','low','medium','high','critical'}:
            raise ValueError('unsupported finding severity')
        if data['confidence'] not in {'hypothesis','confirmed','disproved','unresolved'}:
            raise ValueError('unsupported finding confidence')
        if data['remediation_status'] not in {'unplanned','planned','in-progress','remediated','accepted-risk'}:
            raise ValueError('unsupported remediation status')
        if data['retest_status'] not in {'not-tested','passed','failed','inconclusive'}:
            raise ValueError('unsupported retest result')
        if data['evidence_policy'] not in {'sufficient','screenshot'}:
            raise ValueError('unsupported evidence policy')
        references(data['asset_ids'],'asset_ids',assets,required=True)
        references(data['objective_ids'],'objective_ids',objectives,required=True)
        references(data['evidence_ids'],'evidence_ids',evidence)
        covered = {asset for objective in data['objective_ids'] for asset in known[objective]['data']['asset_ids']}
        if not set(data['asset_ids']) <= covered:
            raise ValueError('finding assets must be covered by its objectives')
        if (data['confidence']=='confirmed' or data['retest_status']!='not-tested') and not data['evidence_ids']:
            raise ValueError('confirmed findings and retests require evidence')
        if data['retest_status']=='failed' and data['remediation_status']=='remediated':
            raise ValueError('failed retest must reopen remediation')
        if data['retest_status']=='passed' and data['remediation_status']!='remediated':
            raise ValueError('passed retest requires a remediated finding')
        if data['legacy_id'] is not None:
            config._text(data['legacy_id'],'legacy finding ID',64)
        if data['remediation_status']=='accepted-risk':
            config._keys(data['risk_acceptance'],{'reviewer','reference','reason','expires_at'},'risk acceptance')
            acceptance = data['risk_acceptance']
            if acceptance['reviewer'] != definition['reviewer_id']:
                raise ValueError('risk acceptance requires the configured reviewer')
            text(acceptance['reference'],'risk acceptance reference')
            text(acceptance['reason'],'risk acceptance reason')
            config._moment(acceptance['expires_at'])
        elif data['risk_acceptance'] is not None:
            raise ValueError('risk acceptance belongs only to accepted-risk findings')
    elif kind == 'relationship':
        text(data['label'],'relationship label',maximum=512)
        if data['state'] not in {'observed','inferred','rejected'}:
            raise ValueError('unsupported relationship state')
        references([data['source_id'],data['destination_id']],'relationship nodes',assets|findings,required=True)
        references(data['evidence_ids'],'evidence_ids',evidence)
        if data['state']=='observed' and not data['evidence_ids']:
            raise ValueError('observed relationships require evidence')
    if data['review'] is not None:
        config._keys(data['review'],{'reviewer','reference','created_at_utc'},'record review')
        config._text(data['review']['reference'],'record review reference')
        config._moment(data['review']['created_at_utc'])
        if data['review']['reviewer'] != definition['reviewer_id']:
            raise ValueError('record review requires the configured reviewer')


def states(root):
    records = journal.load(root)
    if not records:
        return {}
    definitions = {event['definition_sha256']:event['definition'] for event in config.load(root)['events']
                   if event['event'] in {'created','approved'}}
    evidence = report_contract._evidence_index(root)
    result = {}
    for event in records:
        kind = event['entity_kind']
        if kind not in DEFAULTS:
            continue
        definition = definitions[event['configuration']['sha256']]
        validate_data(root,kind,event['data'],definition,result,evidence,entity_id=event['entity_id'])
        review = event['data']['review']
        if review and (review['reviewer'] != event['actor'] or review['created_at_utc'] != event['created_at_utc']):
            raise ValueError('record review differs from the retained event')
        result[event['entity_id']] = event
    return result


def change(root,kind,patch,*,actor,reason,expected_revision,expected_event,entity_id=None,
           review=False,review_reference=None,apply=False,now=None):
    root = Path(root).absolute()
    now = config._moment(config._stamp(now))
    if apply:
        with workspace_transaction.write_guard(root):
            preview = change(root,kind,patch,actor=actor,reason=reason,expected_revision=expected_revision,
                             expected_event=expected_event,entity_id=entity_id,review=review,review_reference=review_reference,now=now)
            return journal.write(root,kind,preview['record']['data'],actor=actor,reason=reason,
                                 expected_revision=expected_revision,expected_event=expected_event,entity_id=entity_id,apply=True,now=now)
    if kind not in DEFAULTS:
        raise ValueError('unsupported assessment record kind')
    loaded = config.load(root)
    if loaded is None:
        raise ValueError('managed assessment records require configuration adoption')
    definition = loaded['definition']
    known = states(root)
    existing = known.get(entity_id)
    if entity_id is not None and (not existing or existing['entity_kind'] != kind):
        raise ValueError('unknown record or wrong record kind')
    if not isinstance(patch,dict) or not set(patch) <= set(DEFAULTS[kind])-{'review'}:
        raise ValueError('record patch has unsupported fields; use the review command for reviews')
    data = copy.deepcopy(existing['data'] if existing else DEFAULTS[kind])
    data.update(copy.deepcopy(patch))
    data['review'] = None
    if review:
        if existing is None or patch:
            raise ValueError('review must identify an existing unchanged record')
        if actor != definition['reviewer_id']:
            raise ValueError('review requires the configured reviewer')
        data['review'] = {'reviewer':actor,'reference':config.optional_reference(review_reference,'review reference') or f'local-record:{entity_id}:{expected_event+1}',
                          'created_at_utc':config._stamp(now)}
    if kind=='finding' and data['remediation_status']=='accepted-risk' and actor!=definition['reviewer_id']:
        raise ValueError('risk acceptance requires an explicit reviewer action')
    evidence = report_contract._evidence_index(root)
    validate_data(root,kind,data,definition,known,evidence,entity_id=entity_id)
    if existing and data == existing['data']:
        raise ValueError('record patch has no changes')
    return journal.write(root,kind,data,actor=actor,reason=reason,expected_revision=expected_revision,
                         expected_event=expected_event,entity_id=entity_id,now=now)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind',choices=tuple(DEFAULTS))
    parser.add_argument('command',choices=('record','revise','review','list','history'))
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--input',type=Path)
    parser.add_argument('--id')
    parser.add_argument('--actor')
    parser.add_argument('--reason')
    parser.add_argument('--expected-revision',type=int)
    parser.add_argument('--expected-event',type=int)
    parser.add_argument('--review-reference')
    parser.add_argument('--apply',action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command in {'list','history'}:
            values = list(states(args.workspace).values()) if args.command=='list' else journal.load(args.workspace)
            result = {'event_sequence':len(journal.load(args.workspace)), 'records':[event for event in values if event['entity_kind']==args.kind and (not args.id or event['entity_id']==args.id)]}
        else:
            if any(value is None for value in (args.actor,args.reason,args.expected_revision,args.expected_event)):
                raise ValueError('writes require actor, reason and exact revision/event counters')
            if args.command in {'revise','review'} and not args.id:
                raise ValueError('revise/review requires --id')
            if args.command=='record' and args.id:
                raise ValueError('record assigns a new identifier')
            if args.command!='review' and not args.input:
                raise ValueError('record/revise requires a JSON input')
            result = change(args.workspace,args.kind,config.read_input(args.input) if args.input else {},
                            actor=args.actor,reason=args.reason,expected_revision=args.expected_revision,expected_event=args.expected_event,
                            entity_id=args.id,review=args.command=='review',review_reference=args.review_reference,apply=args.apply)
        print(json.dumps(result,indent=2))
        return 0
    except (OSError,ValueError,RuntimeError) as exc:
        print(f'error: {exc}',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
