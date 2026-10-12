"""Small shared projections of managed assessment records for host/global views."""
if __package__:
    from . import assessment_journal as journal
    from . import assessment_model as model
    from . import engagement_config as config
else:
    import assessment_journal as journal
    import assessment_model as model
    import engagement_config as config


def snapshot(root,history):
    loaded=config.load(root)
    if loaded is None:
        return {'configuration_revision':None,'journal_sequence':0,'journal_sha256':None,'records':[],'hosts':{}}
    records=journal.load(root)
    entities=model.states(root)
    assets={key:value for key,value in entities.items() if value['entity_kind']=='asset'}
    def asset_hosts(identifier,seen=None):
        seen=set() if seen is None else seen
        if identifier in seen:
            return set()
        seen.add(identifier)
        data=assets[identifier]['data']
        result={history[value] for value in data['host_ids'] if value in history}
        for parent in data['parent_ids']:
            result.update(asset_hosts(parent,seen))
        return result
    hosts={host:[] for host in set(history.values())}
    views=[]
    for event in journal.states(root).values():
        kind=event['entity_kind']
        if kind not in {'asset','objective','finding','activity'}:
            continue
        data=event['data']
        associated=asset_hosts(event['entity_id']) if kind=='asset' else set()
        for identifier in data.get('asset_ids',[]):
            associated.update(asset_hosts(identifier))
        associated.update(history[value] for value in data.get('host_ids',[]) if value in history)
        view={'id':event['entity_id'],'revision':event['entity_revision'],'kind':kind,'event_sha256':event['event_sha256'],
              'label':data.get('title',data.get('name',data.get('summary',''))),
              'state':data.get('confidence',data.get('status','recorded')),
              'review_required':kind in {'objective','finding'} and data.get('review') is None}
        views.append(view)
        for host in associated:
            hosts[host].append(view)
    return {'configuration_revision':loaded['definition']['revision'],'journal_sequence':len(records),
            'journal_sha256':records[-1]['event_sha256'] if records else None,'records':views,'hosts':hosts}
