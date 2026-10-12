import json

import pytest

from scripts import assessment_journal as journal
from scripts import assessment_model as model
from scripts import assessment_reporting as reporting
from scripts import (
    create_checkpoint,
    host_state,
    report_contract,
    restore_checkpoint,
    secret_provider,
)
from scripts import workspace_vault as vault
from tests.test_assessment_activity import sample
from tests.test_assessment_model import assessment, record
from tests.test_engagement_config import NOW
from tests.test_workspace_vault import VALUE, intake


def test_asset_findings_and_activities_update_host_and_global_freshness(tmp_path):
    root,asset,objectives=assessment(tmp_path)
    index=host_state._source_snapshot(root)
    before=host_state.host_digest(index,'H01')
    finding=record(root,'finding',{'title':'Synthetic linked finding','asset_ids':[asset['entity_id']],
                                  'objective_ids':[objectives[0]['entity_id']]})
    changed=host_state._source_snapshot(root)
    assert host_state.host_digest(changed,'H01')!=before
    rendered,_=host_state.render_host(changed,'H01',NOW)
    assert finding['entity_id'] in rendered and 'review required=True' in rendered
    value=reporting.build(root,now=NOW)
    path=tmp_path/'manifest.json'
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    report_contract.apply_manifest(root,path,apply=True,replace=False)
    assert host_state._source_snapshot(root)['assessment']['records']


def test_checkpoint_restores_new_records_and_vault_without_reactivating_approval(tmp_path):
    from scripts import assessment_activity
    root,value,options=sample(tmp_path)
    assessment_activity.record(root,value,apply=True,**options)
    vault.apply(root,vault.plan(root,input_bytes=intake(),now=NOW),input_bytes=intake())
    history=(root/journal.LEDGER).read_bytes()
    saved=create_checkpoint.create_checkpoint(root,tmp_path/'checkpoints',NOW,profile='strict',
        unresolved_session_token_count=0,contains_ephemeral_session_secrets=False)[1]
    collection=tmp_path/'restored-collection'
    collection.mkdir(mode=0o700)
    restored=restore_checkpoint.restore(saved,collection,'restored-new-schemas',apply=True)
    destination=collection/'restored-new-schemas'
    assert restored
    assert (destination/journal.LEDGER).read_bytes()==history
    assert model.states(destination)
    assert secret_provider.extend_credentials(destination,[])[0]['secret']==VALUE
    from scripts import engagement_config as config
    assert config.status(destination,now=NOW)['status']!='active'


def test_source_origin_and_kind_are_explicit_without_accepting_target_files(tmp_path):
    from scripts import source_intake
    source=tmp_path/'synthetic.txt'
    source.write_text('Synthetic source material')
    options={'lab':'synthetic','source_value':str(source),'dest_value':None,
             'rw_root':tmp_path/'rw','ro_root':tmp_path/'ro','source_kind':'documentation'}
    plan=source_intake.build_plan(**options,origin='preexisting-nontarget',assessment_reference='synthetic:scope')
    assert plan.origin=='preexisting-nontarget' and plan.assessment_reference=='synthetic:scope'
    with pytest.raises(source_intake.IntakeError,match='target files'):
        source_intake.build_plan(**options,origin='target-file')
