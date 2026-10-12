import copy
import json
import xml.etree.ElementTree as ET
from datetime import timedelta

import pytest

from scripts import assessment_graph as graph
from scripts import assessment_journal as journal
from scripts import assessment_model as model
from scripts import assessment_reporting as reporting
from scripts import engagement_config as config
from scripts import operational_trace, report_contract, workspace_transaction
from tests.test_assessment_decisions import reviewed
from tests.test_configuration_report import prepared
from tests.test_engagement_config import NOW
from tests.test_operational_trace import add_attempt, add_evidence


def record(root,kind,patch,**kwargs):
    return model.change(root,kind,patch,actor=kwargs.pop('actor','OP-SYNTHETIC'),reason='Synthetic record review',
                        expected_revision=config.load(root)['definition']['revision'],expected_event=len(journal.load(root)),
                        now=kwargs.pop('now',NOW+timedelta(seconds=len(journal.load(root)))),apply=True,**kwargs)['record']


def assessment(tmp_path):
    root=prepared(tmp_path)
    asset=record(root,'asset',{'name':'Synthetic application','locator':'https://app.example.test/',
                             'scope_assets':['https://app.example.test/'],'host_ids':['H01']})
    objectives=[record(root,'objective',{'title':title,'asset_ids':[asset['entity_id']]})
                for title in config.load(root)['definition']['objectives']]
    return root,asset,objectives


def test_multiple_objectives_and_finding_retest_history(tmp_path):
    root,asset,objectives=assessment(tmp_path)
    evidence=add_evidence(root,'H01',1)
    finding=record(root,'finding',{'title':'Synthetic access boundary','confidence':'confirmed',
        'asset_ids':[asset['entity_id']],'objective_ids':[item['entity_id'] for item in objectives],
        'evidence_ids':[evidence],'impact':'Synthetic impact','recommendation':'Synthetic remediation'})
    fixed=record(root,'finding',{'remediation_status':'remediated','retest_status':'passed'},entity_id=finding['entity_id'])
    failed=record(root,'finding',{'remediation_status':'in-progress','retest_status':'failed'},entity_id=finding['entity_id'])
    assert failed['entity_revision']==3
    assert fixed['data']['retest_status']=='passed'
    assert model.states(root)[finding['entity_id']]['data']['retest_status']=='failed'
    assert len([event for event in journal.load(root) if event['entity_id']==finding['entity_id']])==3
    with pytest.raises(ValueError,match='reopen'):
        record(root,'finding',{'remediation_status':'remediated'},entity_id=finding['entity_id'])


def test_partial_objectives_produce_honest_report_without_loot_or_screenshots(tmp_path):
    root,_asset,objectives=assessment(tmp_path)
    for objective in objectives:
        record(root,'objective',{'status':'not-tested','limitation':'Synthetic test deliberately not executed'},entity_id=objective['entity_id'])
        record(root,'objective',{},entity_id=objective['entity_id'],actor='RV-SYNTHETIC',review=True)
    value=reporting.build(root,now=NOW)
    assert value['assessment']['scope_reference'] is None
    assert reporting.readiness(root,value)['ready']
    assert len(value['objectives'])==2
    assert (root/'loot.jsonl').read_bytes()==b''
    result=reporting.publish(root,'report/synthetic-report.html',apply=True,now=NOW)
    assert result['checks']['ready']
    raw=(root/'report/synthetic-report.html').read_text()
    assert 'not-tested' in raw and 'No external document' in raw
    snapshot=json.loads((root/'report/synthetic-report.json').read_text())
    assert reporting.validate(root,snapshot)==snapshot
    assert report_contract.validate_manifest(root,snapshot)==snapshot
    with pytest.raises(ValueError,match='exists'):
        reporting.publish(root,'report/synthetic-report.html',apply=True,now=NOW)


def test_report_rejects_fabricated_records_even_after_rehashing(tmp_path):
    root,_,_=assessment(tmp_path)
    value=reporting.build(root,now=NOW)
    changed=copy.deepcopy(value)
    changed['objectives'][0]['data']['status']='complete'
    changed['snapshot_sha256']=config.digest({key:item for key,item in changed.items() if key!='snapshot_sha256'})
    with pytest.raises(ValueError,match='retained record'):
        reporting.validate(root,changed)


def test_finding_review_is_cleared_on_correction_and_real_clock_works(tmp_path):
    root,asset,objectives=assessment(tmp_path)
    finding=record(root,'finding',{'title':'Synthetic hypothesis','asset_ids':[asset['entity_id']],
                                  'objective_ids':[objectives[0]['entity_id']]})
    result=record(root,'finding',{},entity_id=finding['entity_id'],actor='RV-SYNTHETIC',review=True,now=None)
    assert result['data']['review']['created_at_utc']==result['created_at_utc']
    assert model.states(root)[finding['entity_id']]['data']['review']
    result=record(root,'finding',{'severity':'high'},entity_id=finding['entity_id'])
    assert result['data']['review'] is None


def test_graph_is_deterministic_escaped_and_evidence_linked(tmp_path):
    root,asset,objectives=assessment(tmp_path)
    evidence=add_evidence(root,'H01',1)
    finding=record(root,'finding',{'title':'<script>alert(1)</script>','asset_ids':[asset['entity_id']],
                                  'objective_ids':[objectives[0]['entity_id']]})
    relation=record(root,'relationship',{'source_id':asset['entity_id'],'destination_id':finding['entity_id'],
        'label':'Synthetic observed relationship','state':'observed','evidence_ids':[evidence]})
    first=graph.export(root,'report/attack_path.svg')
    second=graph.export(root,'report/attack_path.svg')
    assert first['_svg']==second['_svg']
    assert '<script>' not in first['_svg']
    assert relation['entity_id'] in first['_svg'] and evidence in first['_svg']
    parsed=ET.fromstring(first['_svg'])
    assert not any(element.tag.endswith(('script','foreignObject')) for element in parsed.iter())
    assert not any(key.endswith('href') for element in parsed.iter() for key in element.attrib)
    graph.export(root,'report/attack_path.svg',apply=True)
    assert (root/'report/attack_path.svg').is_file()


def test_managed_attack_path_flows_into_svg(tmp_path):
    root=prepared(tmp_path)
    decision=reviewed(root)
    attempt=add_attempt(root,'H01',1)
    evidence=add_evidence(root,'H01',2)
    _,path=operational_trace.log_attack_path(workspace=root,authorization_id=decision['record']['data']['authorization_id'],
        transition='initial_access',impact_level='low',source_host_id='OPERATOR',source_identity='operator',
        destination_host_id='H01',destination_identity='synthetic-app',source_segment='local',destination_segment='web',
        service='https',technique='reviewed-web-proof',status='success',credential_id=None,attempt_id=attempt,
        evidence_ids=[evidence],now=NOW+timedelta(seconds=3))
    result=graph.export(root,'report/documented-path.svg')
    assert path['path_event_id'] in result['_svg']
    assert result['edges']==1


@pytest.mark.parametrize('locator',['https://unlisted.example.test/','https://app.example.test/api/../outside','https://app.example.test/api/%2e%2e/outside'])
def test_asset_cannot_expand_scope(tmp_path,locator):
    root,_,_=assessment(tmp_path)
    with pytest.raises(ValueError,match='scope'):
        record(root,'asset',{'name':'Outside','locator':locator,'scope_assets':['https://app.example.test/']})


def test_report_transaction_recovers_both_outputs(tmp_path,monkeypatch):
    root,_,_=assessment(tmp_path)
    def crash(*_):
        raise RuntimeError('synthetic report interruption')
    with monkeypatch.context() as patch:
        patch.setattr(workspace_transaction,'_after_operation',crash)
        with pytest.raises(RuntimeError,match='interruption'):
            reporting.publish(root,'report/recovery.html',apply=True,now=NOW)
    pending=workspace_transaction.incomplete(root)
    assert len(pending)==1
    workspace_transaction.replay(root,pending[0])
    assert (root/'report/recovery.html').exists() and (root/'report/recovery.json').exists()


def test_close_preview_tracks_model_revisions(tmp_path):
    from scripts import workspace_lifecycle

    root,_,objectives=assessment(tmp_path)
    before=workspace_lifecycle.build_close_plan(root,now=NOW)
    record(root,'objective',{'limitation':'A reviewed synthetic note'},entity_id=objectives[0]['entity_id'])
    after=workspace_lifecycle.build_close_plan(root,now=NOW)
    assert before.projection_source_sha256 != after.projection_source_sha256
