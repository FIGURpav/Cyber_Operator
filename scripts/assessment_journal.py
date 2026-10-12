"""Typed, append-only assessment records on the existing transaction foundation."""
from __future__ import annotations

import copy
import os
import re
import stat
import uuid
from pathlib import Path

if __package__:
    from . import engagement_config as config
    from . import ledger_io, workspace_transaction
else:
    import engagement_config as config
    import ledger_io
    import workspace_transaction

LEDGER = 'assessment_events.jsonl'
MAX_BYTES = 32 * 1024 * 1024
KINDS = {'decision':'DEC','asset':'AST','objective':'OBJ','finding':'FND','activity':'ACT','relationship':'REL','retention':'RET'}
FIELDS = {'schema_version','sequence','entity_kind','entity_id','entity_revision','actor','reason','created_at_utc','configuration','instance_id','lifecycle_epoch','data','previous_sha256','event_sha256'}


class JournalError(ValueError):
    """The journal is malformed, stale, or unavailable for a supported write."""


def identifier(kind):
    if kind not in KINDS:
        raise JournalError('unsupported entity kind')
    return KINDS[kind] + '-' + uuid.uuid4().hex


def validate_event(event):
    config._keys(event, FIELDS, 'assessment event')
    kind = event['entity_kind']
    if event['schema_version'] != '1.0' or kind not in KINDS:
        raise JournalError('unsupported assessment event schema or kind')
    if not isinstance(event['entity_id'], str) or not re.fullmatch(KINDS[kind] + r'-[0-9a-f]{32}', event['entity_id']):
        raise JournalError('malformed assessment entity identifier')
    for key in ('sequence','entity_revision'):
        if type(event[key]) is not int or event[key] < 1:
            raise JournalError('event sequence and revision must be positive integers')
    config._text(event['actor'], 'actor')
    config._text(event['reason'], 'reason')
    config._moment(event['created_at_utc'])
    config._text(event['instance_id'], 'instance')
    if event['lifecycle_epoch'] is not None:
        config._text(event['lifecycle_epoch'], 'lifecycle epoch')
    config._keys(event['configuration'], {'engagement_id','revision','sha256'}, 'configuration reference')
    reference = event['configuration']
    if (not isinstance(reference['engagement_id'], str) or not re.fullmatch(r'ENG-[0-9a-f]{32}',reference['engagement_id'])
            or type(reference['revision']) is not int or reference['revision'] < 1
            or not isinstance(reference['sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',reference['sha256'])):
        raise JournalError('malformed configuration reference')
    if not isinstance(event['data'], dict) or len(config.encoded(event['data'])) > 256 * 1024:
        raise JournalError('assessment data must be a bounded object')
    if event['event_sha256'] != config.digest({k:v for k,v in event.items() if k != 'event_sha256'}):
        raise JournalError('assessment event hash mismatch')


def load(root):
    root = Path(root).absolute()
    if workspace_transaction.incomplete(root):
        raise JournalError('unfinished transaction; recover before reading assessment records')
    path = workspace_transaction.safe_path(root,LEDGER)
    if not path.exists():
        return []
    info = path.lstat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise JournalError('assessment history requires owner-only mode 0600')
    raw = config._read(path,MAX_BYTES)
    if raw and not raw.endswith(b'\n'):
        raise JournalError('assessment history has an incomplete tail')
    records = []
    revisions = {}
    loaded = config.load(root)
    definitions = {event['definition_sha256']:event['definition'] for event in loaded['events']
                   if event['event'] in {'created','approved'}} if loaded else {}
    for line in raw.splitlines():
        event = ledger_io.loads_json(line)
        validate_event(event)
        reference = event['configuration']
        definition = definitions.get(reference['sha256'])
        if not definition or reference['engagement_id'] != definition['engagement_id'] or reference['revision'] != definition['revision']:
            raise JournalError('assessment event configuration reference is not in retained history')
        entity = event['entity_id']
        if (event['sequence'] != len(records) + 1
                or event['previous_sha256'] != (records[-1]['event_sha256'] if records else None)
                or event['entity_revision'] != revisions.get(entity,0) + 1):
            raise JournalError('assessment history sequence, revision or chain mismatch')
        revisions[entity] = event['entity_revision']
        records.append(event)
    return records


def states(root, kind=None):
    return {item['entity_id']:item for item in load(root) if kind is None or item['entity_kind'] == kind}


def write(root, kind, data, *, actor, reason, expected_revision, expected_event,
          entity_id=None, apply=False, now=None):
    root = Path(root).absolute()
    if apply:
        with workspace_transaction.write_guard(root):
            result = write(root,kind,data,actor=actor,reason=reason,expected_revision=expected_revision,
                           expected_event=expected_event,entity_id=entity_id,now=now)
            event = result['record']
            size = (root / LEDGER).stat().st_size if (root / LEDGER).exists() else 0
            if size + len(config.encoded(event)) > MAX_BYTES:
                raise JournalError('assessment history size limit reached')
            transaction = workspace_transaction.Transaction(root,'assessment-record')
            transaction.add('append',root / LEDGER,config.encoded(event))
            result['transaction_id'] = transaction.commit()
            result['mode'] = 'APPLY'
            return result
    loaded = config.load(root)
    if loaded is None:
        raise JournalError('assessment records require an explicitly managed workspace')
    current = loaded['definition']
    events = load(root)
    if (type(expected_revision) is not int or current['revision'] != expected_revision
            or type(expected_event) is not int or len(events) != expected_event):
        raise JournalError('assessment or configuration changed; refresh and review')
    instance, epoch, closed, inactive = config._environment(root)
    if closed or inactive:
        raise JournalError('assessment records require an open, activated workspace')
    if kind not in KINDS:
        raise JournalError('unsupported assessment entity kind')
    existing = next((event for event in reversed(events) if event['entity_id'] == entity_id),None)
    if entity_id is not None and existing is None:
        raise JournalError('cannot update an unknown assessment entity')
    if existing and existing['entity_kind'] != kind:
        raise JournalError('entity kind cannot change')
    if __package__:
        from . import report_contract
    else:
        import report_contract
    report_contract.reject_secrets(root, {'data':data,'actor':actor,'reason':reason})
    event = {
        'schema_version':'1.0','sequence':len(events)+1,'entity_kind':kind,
        'entity_id':entity_id or identifier(kind),'entity_revision':existing['entity_revision']+1 if existing else 1,
        'actor':actor,'reason':reason,'created_at_utc':config._stamp(now),
        'configuration':{'engagement_id':current['engagement_id'],'revision':current['revision'],'sha256':config.digest(current)},
        'instance_id':instance,'lifecycle_epoch':epoch,'data':copy.deepcopy(data),
        'previous_sha256':events[-1]['event_sha256'] if events else None,
    }
    event['event_sha256'] = config.digest(event)
    validate_event(event)
    return {'mode':'PREVIEW','record':event}
