"""Local metadata decisions do not execute target actions."""
from datetime import timedelta

import pytest

from scripts import assessment_decisions as decisions
from scripts import assessment_journal as journal
from scripts import engagement_config as config
from scripts import operational_trace, workspace_transaction
from tests.test_configuration_report import prepared
from tests.test_engagement_config import NOW, approve, propose


def payload():
    return {'purpose':'target-activity','scope_assets':['https://app.example.test/'], 'host_ids':['H01'],
            'category':'initial-access','impact':'low','technique':'reviewed-web-proof',
            'summary':'Record a synthetic minimal web validation', 'starts_at':'2020-01-01T00:00:00Z',
            'ends_at':'2099-01-01T00:00:00Z','capabilities':[], 'callback_cidrs':[],'callback_ports':[]}


def act(root,event,**kwargs):
    return decisions.change(root,event,actor='OP-SYNTHETIC' if event == 'proposed' else 'RV-SYNTHETIC',
                            reason='Synthetic explicit decision',expected_revision=config.load(root)['definition']['revision'],
                            expected_event=len(journal.load(root)),apply=True,now=NOW+timedelta(seconds=len(journal.load(root))),**kwargs)


def reviewed(root):
    proposal = act(root,'proposed',proposal=payload())
    return act(root,'approved',decision_id=proposal['record']['entity_id'])


def test_reviewed_decision_has_auditable_legacy_projection(tmp_path):
    root = prepared(tmp_path)
    assert operational_trace.load_authorizations(root) == []
    result = reviewed(root)
    record = result['record']
    auth_id = record['data']['authorization_id']
    assert record['data']['review']['reference'].startswith('local-decision:')
    assert (root / 'authorizations.jsonl').read_bytes() == b''
    assert operational_trace.load_authorizations(root)[0]['authorization_id'] == auth_id
    decisions.require_current(root,auth_id,now=NOW+timedelta(seconds=3))
    act(root,'revoked',decision_id=record['entity_id'])
    assert len(operational_trace.load_authorizations(root)) == 1
    with pytest.raises(ValueError,match='revoked'):
        decisions.require_current(root,auth_id,now=NOW+timedelta(seconds=5))


def test_changed_configuration_invalidates_pending_and_approved_decisions(tmp_path):
    root = prepared(tmp_path)
    first = reviewed(root)
    pending = act(root,'proposed',proposal=payload())
    change = propose(root,{'retention_days':60})
    approve(root,proposal_sequence=change['record']['sequence'])
    with pytest.raises(ValueError,match='stale'):
        act(root,'approved',decision_id=pending['record']['entity_id'])
    with pytest.raises(ValueError,match='stale'):
        decisions.require_current(root,first['record']['data']['authorization_id'],now=NOW)


@pytest.mark.parametrize('change',[
    {'scope_assets':['https://unlisted.example.test/']}, {'impact':'high'},
    {'capabilities':['interactive-shells']}, {'category':'lateral-movement'},
    {'callback_cidrs':['192.0.2.0/24'],'callback_ports':[443]},
])
def test_decision_cannot_expand_reviewed_scope_or_policy(tmp_path,change):
    root = prepared(tmp_path)
    with pytest.raises(ValueError):
        act(root,'proposed',proposal={**payload(),**change})
    assert journal.load(root) == []


def test_decision_requires_actual_reviewer_and_fresh_sequence(tmp_path):
    root = prepared(tmp_path)
    result = act(root,'proposed',proposal=payload())
    with pytest.raises(ValueError,match='reviewer'):
        decisions.change(root,'approved',actor='OTHER',reason='Synthetic',expected_revision=1,expected_event=1,
                         decision_id=result['record']['entity_id'],apply=True,now=NOW)
    with pytest.raises(ValueError,match='changed'):
        decisions.change(root,'approved',actor='RV-SYNTHETIC',reason='Synthetic',expected_revision=1,expected_event=0,
                         decision_id=result['record']['entity_id'],apply=True,now=NOW)


def test_interrupted_decision_append_is_recoverable(tmp_path,monkeypatch):
    root = prepared(tmp_path)
    def crash(*_):
        raise RuntimeError('synthetic interruption')
    with monkeypatch.context() as patch:
        patch.setattr(workspace_transaction,'_after_operation',crash)
        with pytest.raises(RuntimeError,match='interruption'):
            act(root,'proposed',proposal=payload())
    pending = workspace_transaction.incomplete(root)
    assert len(pending) == 1
    workspace_transaction.replay(root,pending[0])
    assert len(journal.load(root)) == 1


def test_managed_change_plan_uses_reviewed_decision(tmp_path):
    root = prepared(tmp_path)
    result = reviewed(root)
    _, record = operational_trace.log_change(workspace=root,event='planned',
        authorization_id=result['record']['data']['authorization_id'],host_id='H01',category='initial-access',
        impact_level='low',technique='reviewed-web-proof',target='https://app.example.test/',
        description='Synthetic record only',reversibility='reversible',before_state='Synthetic unchanged state',
        rollback_steps=['No target changes were performed'],validation_steps=['Review synthetic metadata'],now=NOW)
    assert record['authorization_id'] == result['record']['data']['authorization_id']


def test_revocation_after_scope_change_preserves_readable_history(tmp_path):
    root = prepared(tmp_path)
    result = reviewed(root)
    change = propose(root,{'in_scope':['https://other.example.test/']})
    approve(root,proposal_sequence=change['record']['sequence'])
    act(root,'revoked',decision_id=result['record']['entity_id'])
    assert decisions.decision_states(root)[result['record']['entity_id']]['data']['status'] == 'revoked'
    assert len(operational_trace.load_authorizations(root)) == 1


def test_instance_and_lifecycle_change_invalidate_decisions(tmp_path,monkeypatch):
    root = prepared(tmp_path)
    result = reviewed(root)
    original = config._environment(root)
    monkeypatch.setattr(config,'_environment',lambda _:('new-instance',original[1],False,False))
    with pytest.raises(ValueError,match='historical'):
        decisions.require_current(root,result['record']['data']['authorization_id'],now=NOW)
    assert len(operational_trace.load_authorizations(root)) == 1


def test_status_keeps_write_readiness_separate_from_review(tmp_path):
    from scripts import assessment_status, engagement_intake

    root = engagement_intake.initialize(tmp_path,{'name':'status'},apply=True)
    result = assessment_status.snapshot(root,now=NOW)
    assert result['runtime']['write_ready']
    assert not result['configuration']['configuration_approved']
    assert result['questions']
    assert result['review_choices']['artifact_handling']['value'] == 'no-download'
    assert not result['decisions']['configuration_review_implies_activity_approval']


def test_real_clock_review_receipt_matches_its_event(tmp_path):
    root = prepared(tmp_path)
    result = decisions.change(root,'proposed',proposal=payload(),actor='OP-SYNTHETIC',reason='Real clock metadata test',
                              expected_revision=1,expected_event=0,apply=True)
    approved = decisions.change(root,'approved',decision_id=result['record']['entity_id'],actor='RV-SYNTHETIC',
                                reason='Explicit synthetic review',expected_revision=1,expected_event=1,apply=True)
    assert len(decisions.decision_states(root)) == 1
    assert approved['record']['data']['review']['created_at_utc'] == approved['record']['created_at_utc']
