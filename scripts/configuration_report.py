"""Configuration-bound report metadata; retain schema-2.0 historical readers."""
from datetime import UTC, datetime

if __package__:
    from . import engagement_config as config
else:
    import engagement_config as config


def reviewed_snapshot(root, reference):
    loaded = config.load(root)
    if loaded is None:
        raise ValueError('configuration-bound reports require a managed workspace')
    config._keys(reference, {'engagement_id','revision','sha256','approval_event'}, 'report configuration reference')
    sequence = reference['approval_event']
    if type(sequence) is not int or not 1 <= sequence <= len(loaded['events']):
        raise ValueError('report configuration review does not exist')
    event = loaded['events'][sequence - 1]
    if event['event'] != 'approved':
        raise ValueError('report reference must identify an approved configuration')
    definition = event['definition']
    expected = {'engagement_id':definition['engagement_id'], 'revision':definition['revision'],
                'sha256':config.digest(definition), 'approval_event':sequence}
    if reference != expected:
        raise ValueError('report configuration reference differs from reviewed history')
    return definition, event


def validate_binding(root, manifest):
    definition, event = reviewed_snapshot(root, manifest['configuration'])
    engagement = manifest['engagement']
    if (manifest['assessment_team']['team_id'] != definition['team_id']
            or engagement['scope_url'] != definition['scope_reference']
            or engagement['scope_version'] != str(definition['revision'])
            or engagement['approved_at_utc'] != event['created_at_utc']
            or engagement['engagement_date'] != definition['starts_at'][:10]):
        raise ValueError('report metadata differs from the reviewed configuration')
    if any(item['objective_name'] not in definition['objectives'] for item in manifest['assessment_objectives']):
        raise ValueError('report objective is absent from the reviewed configuration')


def build(root, host_id, *, now=None):
    loaded = config.load(root)
    if loaded is None:
        raise ValueError('report draft requires a managed workspace')
    instance, epoch, _, _ = config._environment(root)
    control = next((event for event in reversed(loaded['events']) if event['event'] in {'approved','paused','revoked'}), None)
    if not control or control['event'] != 'approved' or control['instance_id'] != instance or control['lifecycle_epoch'] != epoch:
        raise ValueError('review the current configuration before drafting report metadata')
    value = loaded['definition']
    approval = next(event for event in reversed(loaded['events']) if event['event'] == 'approved')
    moment = now or datetime.now(UTC)
    manifest = {
        'schema_version':'2.1', 'report_id':'RPT-' + moment.strftime('%Y%m%dT%H%M%S%fZ'),
        'configuration':{'engagement_id':value['engagement_id'], 'revision':value['revision'],
                         'sha256':config.digest(value), 'approval_event':approval['sequence']},
        'assessment_team':{'team_id':value['team_id'], 'name':value['team_id']},
        'engagement':{'engagement_date':value['starts_at'][:10], 'scope_version':str(value['revision']),
                      'scope_url':value['scope_reference'], 'approved_at_utc':approval['created_at_utc']},
        'chains':[], 'assessment_objectives':[
            {'host_id':host_id,'chain_id':None,'category':'application','objective_name':name,'objective_loot_id':None}
            for name in value['objectives']],
    }
    return manifest


def is_current(root, manifest):
    loaded = config.load(root)
    instance, epoch, _, _ = config._environment(root)
    control = next((event for event in reversed(loaded['events']) if event['event'] in {'approved','paused','revoked'}), None) if loaded else None
    return bool(loaded and control and control['event'] == 'approved'
                and control['instance_id'] == instance and control['lifecycle_epoch'] == epoch
                and manifest['configuration']['sha256'] == config.digest(loaded['definition'])
                and manifest['configuration']['approval_event'] == control['sequence'])
