import json
import stat

import pytest

from scripts import (
    credential_intake,
    operational_trace,
    report_contract,
    secret_provider,
    stream_coordination,
)
from scripts import workspace_transaction as tx
from scripts import workspace_vault as vault
from tests.test_assessment_decisions import act, payload
from tests.test_configuration_report import prepared
from tests.test_engagement_config import NOW

VALUE='Synthetic-Vault-Value-2026!'


def intake():
    return f'host: H01\nusername: synthetic-user\npassword: {VALUE}\nservice: web\n'.encode()


def test_new_vault_intake_redacted_metadata_and_secret_filters(tmp_path):
    root=prepared(tmp_path)
    raw=intake()
    plan=vault.plan(root,input_bytes=raw,now=NOW)
    assert VALUE not in json.dumps(plan)
    result=vault.apply(root,plan,input_bytes=raw)
    assert VALUE not in json.dumps(result)
    assert not (root/vault.LEGACY).exists()
    metadata=secret_provider.metadata(root)
    assert VALUE not in json.dumps(metadata)
    assert secret_provider.WorkspaceVault(root).resolve(metadata[0]['secret_ref'])==VALUE
    assert stat.S_IMODE((root/'private/vault/values').stat().st_mode)==0o700
    assert len(report_contract._credential_records(root))==1
    with pytest.raises(ValueError,match='credential'):
        report_contract.reject_secrets(root,{'note':VALUE})
    with pytest.raises(operational_trace.TraceError,match='credential'):
        operational_trace._reject_secret_content(root,[VALUE])
    with pytest.raises(stream_coordination.CoordinationError,match='credential'):
        stream_coordination._reject_secret_summary(root,[VALUE])
    assert not vault.plan(root,input_bytes=raw,now=NOW)['records']


def test_additive_migration_preserves_original_and_checkpoint(tmp_path):
    root=prepared(tmp_path)
    credential_intake.store_credential_bytes(root,intake(),now=NOW)
    before=(root/vault.LEGACY).read_bytes()
    reviewed=vault.plan(root,migrate=True,now=NOW)
    vault.apply(root,reviewed)
    assert (root/vault.LEGACY).read_bytes()==before
    assert (root/reviewed['checkpoint']).read_bytes()==before
    assert len(report_contract._credential_records(root))==1
    assert not vault.plan(root,migrate=True,now=NOW)['records']


@pytest.mark.parametrize('step',range(2))
def test_vault_recovery_never_publishes_metadata_without_recoverable_value(tmp_path,monkeypatch,step):
    root=prepared(tmp_path)
    reviewed=vault.plan(root,input_bytes=intake(),now=NOW)
    def crash(_identifier,index):
        if index==step:
            raise RuntimeError('Synthetic interruption')
    with monkeypatch.context() as patch:
        patch.setattr(tx,'_after_operation',crash)
        with pytest.raises(RuntimeError,match='Synthetic'):
            vault.apply(root,reviewed,input_bytes=intake())
    identifier=tx.incomplete(root)[0]
    with tx.write_guard(root,recovery=True):
        tx.replay(root,identifier)
    assert report_contract._credential_records(root)[0]['secret']==VALUE


def test_changed_input_and_unavailable_provider_fail_without_leaking_values(tmp_path,monkeypatch):
    root=prepared(tmp_path)
    reviewed=vault.plan(root,input_bytes=intake(),now=NOW)
    with pytest.raises(ValueError,match='plan changed'):
        vault.apply(root,reviewed,input_bytes=intake().replace(b'2026',b'2027'))
    vault.apply(root,reviewed,input_bytes=intake())
    monkeypatch.setenv('CYBER_SECRET_PROVIDER','unavailable-provider')
    with pytest.raises(secret_provider.ProviderError,match='unavailable'):
        report_contract._credential_records(root)


def test_missing_or_world_readable_value_fails_closed(tmp_path):
    root=prepared(tmp_path)
    vault.apply(root,vault.plan(root,input_bytes=intake(),now=NOW),input_bytes=intake())
    value=next((root/'private/vault/values').iterdir())
    value.chmod(0o644)
    with pytest.raises(secret_provider.ProviderError):
        report_contract._credential_records(root)
    value.unlink()
    with pytest.raises(secret_provider.ProviderError):
        report_contract._credential_records(root)


def test_sensitive_export_requires_separate_current_review_and_records_local_file(tmp_path):
    from scripts import assessment_journal as journal
    from scripts import engagement_config as config
    from scripts import vault_disclosure
    root=prepared(tmp_path)
    vault.apply(root,vault.plan(root,input_bytes=intake(),now=NOW),input_bytes=intake())
    credential=secret_provider.metadata(root)[0]['credential_id']
    options={'actor':'RV-SYNTHETIC','reason':'Synthetic reviewed plaintext disclosure',
             'audience':'Synthetic internal reviewer','retention_days':1,
             'expected_revision':config.load(root)['definition']['revision'],'expected_event':0,'now':NOW}
    with pytest.raises(ValueError,match='current reviewed'):
        vault_disclosure.plan(root,[credential],'missing',**options)
    proposed=act(root,'proposed',proposal={**payload(),'purpose':'sensitive-export'})
    identifier=proposed['record']['entity_id']
    act(root,'approved',decision_id=identifier)
    options['expected_event']=len(journal.load(root))
    reviewed=vault_disclosure.plan(root,[credential],identifier,**options)
    assert VALUE not in json.dumps(reviewed)
    result=vault_disclosure.apply(root,reviewed,now=NOW)
    assert VALUE in (root/result['destination']).read_text()
    assert VALUE not in (root/journal.LEDGER).read_text()
    assert not result.get('remote_revocation')
    act(root,'revoked',decision_id=identifier)
    options['expected_event']=len(journal.load(root))
    with pytest.raises(ValueError,match='current reviewed'):
        vault_disclosure.plan(root,[credential],identifier,**options)


def test_brief_rejects_a_vault_value_pasted_into_manual_notes(tmp_path):
    from scripts import build_brief
    root=prepared(tmp_path)
    vault.apply(root,vault.plan(root,input_bytes=intake(),now=NOW),input_bytes=intake())
    (root/'global.md').write_text(VALUE)
    with pytest.raises(SystemExit):
        build_brief.build_brief(root,'H01',5,5,5,5,NOW)
