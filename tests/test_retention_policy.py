import pytest

from scripts import assessment_journal as journal
from scripts import engagement_config as config
from scripts import retention_policy, storage_retention
from tests.test_configuration_report import prepared
from tests.test_engagement_config import NOW


def change(root,held,actor='RV-SYNTHETIC'):
    return retention_policy.change(root,'*',held,actor=actor,reason='Synthetic administrative hold',
        expected_revision=config.load(root)['definition']['revision'],expected_event=len(journal.load(root)),now=NOW,apply=True)


def test_retention_classification_hold_and_explicit_release(tmp_path):
    root=prepared(tmp_path)
    result=retention_policy.status(root)
    assert result['retention_days']>0 and result['review_due']
    assert not result['automatic_purge']
    with pytest.raises(ValueError,match='reviewer'):
        change(root,True,actor='OP-SYNTHETIC')
    change(root,True)
    with pytest.raises(ValueError,match='hold blocks'):
        storage_retention.compact(root,'TXN-'+'0'*32,apply=False,min_age_days=0)
    change(root,False)
    retention_policy.require_clear(root)
    assert len(journal.states(root,'retention'))==2
