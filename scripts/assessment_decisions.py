"""Record exact human decisions for managed assessments; never execute actions."""
from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

if __package__:
    from . import assessment_journal as journal
    from . import engagement_config as config
    from . import host_identity, operational_trace, workspace_transaction
else:
    import assessment_journal as journal
    import engagement_config as config
    import host_identity
    import operational_trace
    import workspace_transaction

PROPOSAL_FIELDS = {'purpose','scope_assets','host_ids','category','impact','technique','summary',
                   'starts_at','ends_at','capabilities','callback_cidrs','callback_ports'}


def _host_matches(root, host_id, scopes):
    endpoints = set(host_identity.host_endpoints(root,host_id))
    endpoints.add(host_identity.resolve_host(root,host_id).hostname)
    for scope in scopes:
        if scope == host_id or scope in endpoints or urlsplit(scope).hostname in endpoints:
            return True
        try:
            network = ipaddress.ip_network(scope,strict=True)
        except ValueError:
            continue
        for endpoint in endpoints:
            try:
                if ipaddress.ip_address(endpoint) in network:
                    return True
            except ValueError:
                pass
    return False


def validate_proposal(root, proposal, definition, *, historical=False):
    config._keys(proposal,PROPOSAL_FIELDS,'decision proposal')
    if proposal['purpose'] not in {'target-activity','secret-disclosure','sensitive-export'}:
        raise ValueError('unsupported decision purpose')
    for key in ('scope_assets','host_ids','capabilities','callback_cidrs'):
        config._strings(proposal[key],key)
    for key in ('technique','summary'):
        config._text(proposal[key],key,1024)
    if not proposal['scope_assets'] or not set(proposal['scope_assets']) <= set(definition['in_scope']):
        raise ValueError('decision scope must be a non-empty subset of the reviewed scope')
    if set(proposal['scope_assets']) & set(definition['excluded']):
        raise ValueError('decision includes an explicitly excluded asset')
    if proposal['purpose'] == 'target-activity' and not proposal['host_ids']:
        raise ValueError('activity decisions require registered host references')
    known = host_identity.known_host_ids(root)
    if any(host not in known or (not historical and not _host_matches(root,host,proposal['scope_assets'])) for host in proposal['host_ids']):
        raise ValueError('decision host is unknown or not linked to its explicit scope')
    if proposal['category'] not in operational_trace.AUTHORIZATION_CATEGORIES:
        raise ValueError('unsupported decision category')
    if proposal['impact'] not in {'low','medium','high','critical'}:
        raise ValueError('decision impact must use the canonical vocabulary')
    if operational_trace.IMPACT_RANK[proposal['impact']] > operational_trace.IMPACT_RANK[definition['maximum_impact']]:
        raise ValueError('decision exceeds the configured impact')
    if set(proposal['capabilities']) & set(definition['policy']['prohibited']):
        raise ValueError('decision conflicts with a template prohibition')
    if (definition['template']['id'] == 'pentest-web-app-standard'
            and proposal['category'] not in {'access-control','data','initial-access','other'}):
        raise ValueError('web template does not permit this operational category')
    start, end = config._moment(proposal['starts_at']), config._moment(proposal['ends_at'])
    if not config._moment(definition['starts_at']) <= start < end <= config._moment(definition['ends_at']):
        raise ValueError('decision time must remain inside the reviewed assessment window')
    ports = proposal['callback_ports']
    if (not isinstance(ports,list) or any(type(p) is not int for p in ports)
            or len(set(ports)) != len(ports) or not set(ports) <= set(definition['callback_ports'])
            or not set(proposal['callback_cidrs']) <= set(definition['callback_cidrs'])
            or bool(ports) != bool(proposal['callback_cidrs'])):
        raise ValueError('decision callback choices exceed the reviewed configuration')
    return proposal


def decision_states(root):
    """Validate transitions and their exact historical configuration bindings."""
    records = journal.load(root)
    loaded = config.load(root)
    definitions = {event['definition_sha256']:event['definition'] for event in loaded['events']
                   if event['event'] in {'created','approved'}} if loaded else {}
    result = {}
    proposal_definitions = {}
    for event in records:
        if event['entity_kind'] != 'decision':
            continue
        data = event['data']
        config._keys(data,{'status','proposal','review','authorization_id'},'decision record')
        definition = definitions.get(event['configuration']['sha256'])
        if definition is None:
            raise ValueError('decision configuration snapshot does not exist')
        proposal_definitions.setdefault(event['entity_id'],definition)
        validate_proposal(root,data['proposal'],proposal_definitions[event['entity_id']],historical=True)
        previous = result.get(event['entity_id'])
        if previous is None:
            if data['status'] != 'proposed' or data['review'] is not None or data['authorization_id'] is not None:
                raise ValueError('decision history must begin with an unreviewed proposal')
        else:
            prior = previous['data']
            allowed = {'proposed':{'approved','rejected'},'approved':{'revoked'}}
            if data['status'] not in allowed.get(prior['status'],set()) or data['proposal'] != prior['proposal']:
                raise ValueError('decision history has an invalid transition or changed proposal')
            config._keys(data['review'],{'actor','reference','created_at_utc','reason'},'decision review')
            if data['review']['actor'] != event['actor'] or event['actor'] != definition['reviewer_id']:
                raise ValueError('decision history has an invalid reviewer')
            config._text(data['review']['reference'],'review reference')
            if data['review']['created_at_utc'] != event['created_at_utc'] or data['review']['reason'] != event['reason']:
                raise ValueError('decision review differs from its event')
            if data['status'] == 'approved':
                if event['configuration'] != previous['configuration'] or event['instance_id'] != previous['instance_id'] or event['lifecycle_epoch'] != previous['lifecycle_epoch']:
                    raise ValueError('decision approval changed its proposal binding')
                expected = 'AUTH-' + config._moment(event['created_at_utc']).strftime('%Y%m%dT%H%M%S%fZ') if data['proposal']['purpose'] == 'target-activity' else None
                if data['authorization_id'] != expected:
                    raise ValueError('decision authorization receipt differs from its review')
            elif data['authorization_id'] != prior['authorization_id']:
                raise ValueError('decision control changed its receipt identifier')
        result[event['entity_id']] = event
    return result


def change(root, event, *, actor, reason, expected_revision, expected_event,
           proposal=None, decision_id=None, approval_reference=None, apply=False, now=None):
    root = Path(root).absolute()
    if apply:
        with workspace_transaction.write_guard(root):
            preview = change(root,event,actor=actor,reason=reason,expected_revision=expected_revision,
                             expected_event=expected_event,proposal=proposal,decision_id=decision_id,
                             approval_reference=approval_reference,now=now)
            return journal.write(root,'decision',preview['record']['data'],actor=actor,reason=reason,
                                 expected_revision=expected_revision,expected_event=expected_event,
                                 entity_id=decision_id,apply=True,now=now)
    loaded = config.load(root)
    if loaded is None:
        raise ValueError('reviewed decisions require a managed workspace')
    definition = loaded['definition']
    current = decision_states(root).get(decision_id)
    if event == 'proposed':
        if decision_id is not None:
            raise ValueError('a new proposal creates its own decision identifier')
        validate_proposal(root,proposal,definition)
        data = {'status':'proposed','proposal':copy.deepcopy(proposal),'review':None,'authorization_id':None}
    elif event in {'approved','rejected','revoked'}:
        if current is None:
            raise ValueError('decision does not exist')
        data = copy.deepcopy(current['data'])
        expected_state = 'approved' if event == 'revoked' else 'proposed'
        if data['status'] != expected_state:
            raise ValueError('decision transition is invalid; submit a new proposal')
        if actor != definition['reviewer_id']:
            raise ValueError('decision requires the configured reviewer')
        if event == 'approved':
            if current['configuration']['sha256'] != config.digest(definition):
                raise ValueError('decision proposal is stale after a configuration change')
            instance,epoch,_,_ = config._environment(root)
            if current['instance_id'] != instance or current['lifecycle_epoch'] != epoch:
                raise ValueError('decision proposal is historical after restore or reopen')
            if config.status(root,now=now)['status'] != 'active':
                raise ValueError('activity review requires a current active configuration')
            validate_proposal(root,data['proposal'],definition)
            if config._moment(config._stamp(now)) >= config._moment(data['proposal']['ends_at']):
                raise ValueError('cannot approve an expired activity decision')
            if data['proposal']['purpose'] == 'target-activity':
                data['authorization_id'] = 'AUTH-' + config._moment(config._stamp(now)).strftime('%Y%m%dT%H%M%S%fZ')
                if data['authorization_id'] in {item['authorization_id'] for item in operational_trace.load_authorizations(root)}:
                    raise ValueError('decision receipt timestamp collision; retry with a fresh timestamp')
        data['status'] = event
        data['review'] = {'actor':actor,'reference':config.optional_reference(approval_reference,'approval reference') or f'local-decision:{decision_id}:{expected_event+1}',
                          'created_at_utc':config._stamp(now),'reason':reason}
    else:
        raise ValueError('unsupported decision transition')
    return journal.write(root,'decision',data,actor=actor,reason=reason,expected_revision=expected_revision,
                         expected_event=expected_event,entity_id=decision_id,now=now)


def virtual_authorizations(root):
    """Read-only compatibility views of explicit approvals, including history."""
    result = []
    decision_states(root)
    for event in journal.load(root):
        data = event['data']
        if event['entity_kind'] != 'decision' or data.get('status') != 'approved' or not data.get('authorization_id'):
            continue
        proposal = data['proposal']
        result.append({'schema_version':'1.0','authorization_id':data['authorization_id'],
                       'created_at_utc':data['review']['created_at_utc'],'host_ids':proposal['host_ids'],
                       'categories':[proposal['category']],'maximum_impact':proposal['impact'],
                       'techniques':[proposal['technique'].lower()],'exclusions':[],
                       'source':'reviewed-decision:' + event['entity_id'],'summary':proposal['summary']})
    return result


def require_current(root, authorization_id, *, now=None):
    if not config.is_managed(Path(root)):
        return
    matches = [event for event in decision_states(root).values() if event['data'].get('authorization_id') == authorization_id]
    if len(matches) != 1:
        raise ValueError('managed activity requires a recorded current decision')
    event = matches[0]
    definition = config.load(root)['definition']
    instance,epoch,_,_ = config._environment(root)
    proposal = event['data']['proposal']
    moment = config._moment(config._stamp(now))
    if (event['data']['status'] != 'approved' or event['configuration']['sha256'] != config.digest(definition)
            or event['instance_id'] != instance or event['lifecycle_epoch'] != epoch
            or config.status(root,now=now)['status'] != 'active'
            or not config._moment(proposal['starts_at']) <= moment < config._moment(proposal['ends_at'])):
        raise ValueError('activity decision is revoked, stale, historical or outside its window')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command',required=True)
    for command in ('list','propose','approve','reject','revoke'):
        item = sub.add_parser(command)
        item.add_argument('--workspace',type=Path,required=True)
        if command != 'list':
            item.add_argument('--actor',required=True)
            item.add_argument('--reason',required=True)
            item.add_argument('--expected-revision',type=int,required=True)
            item.add_argument('--expected-event',type=int,required=True,help='assessment journal sequence, not configuration event sequence')
            item.add_argument('--apply',action='store_true')
        if command == 'propose':
            item.add_argument('--input',type=Path,required=True)
        elif command != 'list':
            item.add_argument('--decision-id',required=True)
            item.add_argument('--approval-reference')
    args = parser.parse_args(argv)
    try:
        if args.command == 'list':
            result = {'event_sequence':len(journal.load(args.workspace)),'decisions':decision_states(args.workspace)}
        else:
            result = change(args.workspace,{'propose':'proposed','approve':'approved','reject':'rejected','revoke':'revoked'}[args.command],
                            actor=args.actor,reason=args.reason,expected_revision=args.expected_revision,expected_event=args.expected_event,
                            proposal=config.read_input(args.input) if args.command == 'propose' else None,
                            decision_id=getattr(args,'decision_id',None),approval_reference=getattr(args,'approval_reference',None),apply=args.apply)
        print(json.dumps(result,indent=2))
        return 0
    except (OSError,ValueError,RuntimeError) as exc:
        print(f'error: {exc}',file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
