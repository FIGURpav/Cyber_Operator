import pytest

from scripts import (
    ai_session,
    assessment_activity,
    build_brief,
    context_budget,
    structured_state,
    workspace_transaction,
)
from scripts import assessment_journal as journal
from scripts import engagement_config as config
from tests.test_assessment_model import assessment
from tests.test_engagement_config import NOW
from tests.test_operational_trace import add_evidence


def sample(tmp_path):
    root,asset,objectives=assessment(tmp_path)
    evidence=add_evidence(root,'H01',1)
    value={'summary':'Synthetic observation','result':'Synthetic evidence recorded','host_ids':['H01'],
           'asset_ids':[asset['entity_id']],'objective_ids':[objectives[0]['entity_id']],'evidence_ids':[evidence],
           'attempt':{'status':'partial','next_step':'Operator review'},
           'task':{'kind':'assessment-task','external_ref':'synthetic:review','state':'locally_complete'},
           'finding':{'confidence':'confirmed'}}
    options={'actor':'OP-SYNTHETIC','reason':'Synthetic activity','key':'synthetic:one',
             'expected_revision':config.load(root)['definition']['revision'],'expected_event':len(journal.load(root)),'now':NOW}
    return root,value,options


def test_activity_atomic_links_and_idempotency(tmp_path):
    root,value,options=sample(tmp_path)
    preview=assessment_activity.record(root,value,**options)
    assert len(preview['operations'])==4
    result=assessment_activity.record(root,value,apply=True,**options)
    data=result['record']['data']
    assert data['attempt_id'] in structured_state.work_item_states(root)[data['task_id']]['references']
    assert data['finding_ids'][0] in journal.states(root,'finding')
    before=(root/journal.LEDGER).read_bytes()
    assert assessment_activity.record(root,value,apply=True,**options)['mode']=='EXISTING'
    assert (root/journal.LEDGER).read_bytes()==before
    with pytest.raises(ValueError,match='different request'):
        assessment_activity.record(root,{**value,'result':'Changed'},apply=True,**options)


@pytest.mark.parametrize('step',range(4))
def test_activity_interruption_recovery_each_publication_step(tmp_path,monkeypatch,step):
    root,value,options=sample(tmp_path)
    def crash(_identifier,index):
        if index==step:
            raise RuntimeError('synthetic interruption')
    with monkeypatch.context() as patch:
        patch.setattr(workspace_transaction,'_after_operation',crash)
        with pytest.raises(RuntimeError,match='synthetic interruption'):
            assessment_activity.record(root,value,apply=True,**options)
    identifier=workspace_transaction.incomplete(root)[0]
    with workspace_transaction.write_guard(root,recovery=True):
        workspace_transaction.replay(root,identifier)
    assert not workspace_transaction.incomplete(root)
    assert assessment_activity.record(root,value,apply=True,**options)['mode']=='EXISTING'
    assert len(journal.states(root,'activity'))==1
    assert len(structured_state.work_item_states(root))==1


def test_stale_activity_does_not_publish_optional_records(tmp_path):
    root,value,options=sample(tmp_path)
    options['expected_event']-=1
    before=(root/'attempts.jsonl').read_bytes()
    with pytest.raises(ValueError,match='changed'):
        assessment_activity.record(root,value,apply=True,**options)
    assert (root/'attempts.jsonl').read_bytes()==before


def test_megabyte_notes_bounded_and_critical_scope_preserved(tmp_path):
    root,_,_=assessment(tmp_path)
    (root/'global.md').write_text('Synthetic manual notes\n'+'x'*1024*1024)
    text,stats=build_brief.build_brief(root,'H01',5,5,5,5,NOW,max_bytes=16384,section_bytes=2048)
    assert len(text.encode())<=16384
    assert 'app.example.test' in text and 'stop_conditions' in text
    assert 'omitted_bytes' in text and 'Global State' in text
    assert stats['budget']['bytes']==len(text.encode())


def test_exact_token_budget_and_nontruncation_of_critical_state():
    text,stats=context_budget.compose('Critical scope and stop state',[('Notes','abc '*5000)],
                                      max_bytes=8192,token_counter=lambda text:len(text),max_tokens=1200)
    assert len(text)<=1200 and text.startswith('Critical scope')
    assert stats['tokens']==len(text)
    with pytest.raises(ValueError,match='critical'):
        context_budget.compose('critical'*2000,[],max_bytes=2048)


def test_ai_metadata_is_explicit_and_uses_references(tmp_path):
    root,_,_=assessment(tmp_path)
    value={'provider':'unknown','model':'unknown','session_label':'Synthetic session','purpose':'Review supplied evidence',
           'query_ids':[],'response_evidence_ids':[],'decision_ids':[]}
    result=ai_session.record(root,value,actor='OP-SYNTHETIC',reason='Explicit metadata',
                             expected_revision=config.load(root)['definition']['revision'],expected_event=len(journal.load(root)),apply=True)
    assert result['record']['data']==value
    assert not list((root/'queries').glob('QRY-*'))
