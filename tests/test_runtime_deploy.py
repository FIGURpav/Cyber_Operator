import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import release_check
from scripts import runtime_deploy as deploy


def release(tmp_path,version='0.7.0'):
    source=tmp_path/('source-'+version)
    (source/'scripts').mkdir(parents=True)
    (source/'README.md').write_text('Synthetic release\n')
    (source/'pyproject.toml').write_text(f'[project]\nname = "synthetic"\nversion = "{version}"\n')
    (source/'scripts/cyber-synthetic').write_text('#!/bin/sh\nexec python3 -c "import sys; print(sys.version_info.major)"\n')
    (source/'scripts/cyber-python').write_text('#!/usr/bin/env python3\nprint("synthetic-python-wrapper")\n')
    archive=tmp_path/f'release-{version}.zip'
    release_check.package(source,archive)
    return archive


def plan(tmp_path,archive):
    return deploy.preview(archive,tmp_path/'runtime',tmp_path/'deployment-state',tmp_path/'bin',sys.executable,tmp_path/'config.toml')


def test_clean_install_repeatable_verification_and_no_workspace(tmp_path):
    value=plan(tmp_path,release(tmp_path))
    assert not (tmp_path/'runtime').exists()
    result=deploy.install(value)
    assert deploy.verify(tmp_path/'runtime',result['receipt'])['verified']
    output=subprocess.check_output([str(tmp_path/'bin/cyber-synthetic')],text=True)
    assert output.strip()=='3'
    assert subprocess.check_output([str(tmp_path/'bin/cyber-python')],text=True).strip()=='synthetic-python-wrapper'
    assert not (tmp_path/'workspaces').exists()
    changed=tmp_path/'runtime/README.md'
    changed.write_text('Local changes\n')
    with pytest.raises(ValueError,match='differs'):
        plan(tmp_path,value['archive'])


@pytest.mark.parametrize('step',['prepared','old-source-retained','new-source-active','wrappers-active'])
def test_interrupted_upgrade_recovers_and_rolls_back_exact_source(tmp_path,monkeypatch,step):
    first=deploy.install(plan(tmp_path,release(tmp_path,'0.6.0')))
    baseline=deploy.inventory(tmp_path/'runtime')
    second=plan(tmp_path,release(tmp_path))
    def crash(current):
        if current==step:
            raise RuntimeError('Synthetic interruption')
    with monkeypatch.context() as patch:
        patch.setattr(deploy,'_after_step',crash)
        with pytest.raises(RuntimeError,match='Synthetic'):
            deploy.install(second)
    jobs=tmp_path/'deployment-state/deployments'
    receipt=next(path for path in jobs.iterdir() if str(path)!=first['receipt'])
    assert deploy.recover(receipt)['status']=='installed'
    assert deploy.verify(tmp_path/'runtime',receipt)['verified']
    assert deploy.recover(receipt,rollback=True)['status']=='rolled-back'
    assert deploy.inventory(tmp_path/'runtime')==baseline
    assert deploy.verify(tmp_path/'runtime',first['receipt'])['verified']


def test_upgrade_refuses_stale_wrapper_and_tampered_archive(tmp_path):
    archive=release(tmp_path)
    value=plan(tmp_path,archive)
    (tmp_path/'bin').mkdir()
    (tmp_path/'bin/cyber-synthetic').write_text('changed')
    with pytest.raises(ValueError,match='wrapper changed'):
        deploy.install(value)
    assert not (tmp_path/'runtime').exists()
    assert json.loads(deploy.encoded(value))==value


def test_deployment_rejects_source_private_data(tmp_path):
    archive=release(tmp_path)
    result=deploy.install(plan(tmp_path,archive))
    (tmp_path/'runtime/engagement.json').write_text('{}')
    with pytest.raises(ValueError,match='private|unapproved'):
        deploy.verify(tmp_path/'runtime',Path(result['receipt']))


def test_environment_creation_failure_keeps_a_recoverable_preparation_receipt(tmp_path,monkeypatch):
    value=plan(tmp_path,release(tmp_path))
    def fail(*args,**kwargs):
        raise subprocess.CalledProcessError(1,'synthetic environment creation')
    monkeypatch.setattr(deploy.subprocess,'run',fail)
    with pytest.raises(subprocess.CalledProcessError):
        deploy.install(value)
    receipt=next((tmp_path/'deployment-state/deployments').iterdir())
    assert deploy.recover(receipt,rollback=True)['source_unchanged']
    assert not (tmp_path/'runtime').exists()
