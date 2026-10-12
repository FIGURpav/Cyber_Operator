import copy
import json

import pytest

from scripts import configuration_report, new_host, report_contract
from tests.test_engagement_config import NOW, approve, propose, workspace


def prepared(tmp_path):
    root = workspace(tmp_path, scope_reference=None, objectives=['Review sessions','Review authorization'])
    approve(root)
    assert new_host.main(['--workspace',str(root),'--host-id','H01','--ip','192.0.2.10','--hostname','app.example.test']) == 0
    return root


def test_none_multiple_objectives_and_binding(tmp_path):
    root = prepared(tmp_path)
    value = configuration_report.build(root, 'H01', now=NOW)
    assert value['engagement']['scope_url'] is None
    assert len(report_contract.validate_manifest(root,value)['assessment_objectives']) == 2
    for field in ('team','objective','scope','reference'):
        changed = copy.deepcopy(value)
        if field == 'team':
            changed['assessment_team']['team_id'] = 'DIFFERENT'
        elif field == 'objective':
            changed['assessment_objectives'][0]['objective_name'] = 'Unreviewed objective'
        elif field == 'scope':
            changed['engagement']['scope_url'] = 'https://unrelated.example.test/'
        else:
            changed['configuration']['sha256'] = '0' * 64
        with pytest.raises(report_contract.ReportContractError, match='configuration'):
            report_contract.validate_manifest(root,changed)


def test_older_reviewed_snapshot_readable_but_not_current(tmp_path):
    root = prepared(tmp_path)
    value = configuration_report.build(root,'H01',now=NOW)
    assert configuration_report.is_current(root,value)
    candidate = propose(root,{'retention_days':60})
    approve(root,proposal_sequence=candidate['record']['sequence'])
    report_contract.validate_manifest(root,value)
    assert not configuration_report.is_current(root,value)


def test_apply_bound_manifest(tmp_path):
    root = prepared(tmp_path)
    value = configuration_report.build(root,'H01',now=NOW)
    path = tmp_path / 'input.json'
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    assert report_contract.apply_manifest(root,path,apply=False,replace=False) == 'create'
    assert report_contract.apply_manifest(root,path,apply=True,replace=False) == 'create'
    assert report_contract.load_manifest(root) == value
