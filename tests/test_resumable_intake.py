"""Multi-session intake retains answers without activating unreviewed settings."""
import copy

import pytest

from scripts import engagement_config as config
from scripts import engagement_intake
from tests.test_engagement_config import NOW, facts, mutate


def test_incremental_answers_survive_reload_and_exact_review(tmp_path):
    root = engagement_intake.initialize(tmp_path, {'name': 'incremental'}, template_id='pentest-web-app-standard', apply=True)
    original = (root / config.DEFINITION).read_bytes()
    original_event = (root / config.EVENTS).read_bytes()
    batches = [
        {'operator_id': 'OP-SYNTHETIC', 'scope_reference': None},
        {'reviewer_id': 'RV-SYNTHETIC', 'team_id': 'TEAM-SYNTHETIC'},
        {key: value for key, value in facts().items() if key not in {'operator_id','reviewer_id','team_id','scope_reference'}},
    ]
    for batch in batches:
        mutate(root, 'drafted', changes=batch, apply=True)
        assert (root / config.DEFINITION).read_bytes() == original
        assert config.status(root, now=NOW)['configuration_approved'] is False
    working = config.draft_state(root)
    assert working['missing'] == []
    assert working['definition']['scope_reference'] is None
    assert config.scope_reference_state(working['definition']) == 'no-external-document'
    assert config.status(root, now=NOW)['draft']['ready_to_submit']
    proposal = mutate(root, 'proposed', use_draft=True, apply=True)
    mutate(root, 'approved', proposal_sequence=proposal['record']['sequence'], apply=True)
    assert config.status(root, now=NOW)['status'] == 'active'
    assert config.draft_state(root)['event_sequence'] is None
    assert (root / config.EVENTS).read_bytes().startswith(original_event)


def test_answer_preview_cas_and_discard(tmp_path):
    root = engagement_intake.initialize(tmp_path, {'name':'preview'}, apply=True)
    before = (root / config.EVENTS).read_bytes()
    mutate(root, 'drafted', changes={'operator_id':'OP-SYNTHETIC'})
    assert (root / config.EVENTS).read_bytes() == before
    mutate(root, 'drafted', changes={'operator_id':'OP-SYNTHETIC'}, apply=True)
    with pytest.raises(config.ConfigurationError, match='changed'):
        config.change(root, event='drafted', actor='OP-SYNTHETIC', reason='stale', expected_revision=1, expected_event=1, changes={'team_id':'other'}, apply=True)
    mutate(root, 'draft-discarded', apply=True)
    assert config.draft_state(root)['definition']['operator_id'] is None


def test_draft_restrictions_survive_later_answers(tmp_path):
    root = engagement_intake.initialize(tmp_path, {'name':'restricted'}, apply=True)
    mutate(root, 'drafted', changes={'retention_days':30}, basis='engagement-restriction', basis_reference='operator instruction', apply=True)
    with pytest.raises(config.ConfigurationError, match='downgraded'):
        mutate(root, 'drafted', changes={'retention_days':60}, apply=True)
    assert config.draft_state(root)['definition']['retention_days'] == 30


def test_draft_does_not_change_active_download_setting(tmp_path):
    from tests.test_engagement_config import approve, workspace

    root = workspace(tmp_path)
    approve(root)
    before = copy.deepcopy(config.load(root)['definition'])
    mutate(root, 'drafted', changes={'artifact_handling':'standard'}, apply=True)
    assert config.load(root)['definition'] == before
    assert config.draft_state(root)['definition']['artifact_handling'] == 'standard'
