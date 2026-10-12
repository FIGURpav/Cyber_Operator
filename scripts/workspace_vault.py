"""Previewed local plaintext vault intake and additive legacy migration."""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import timedelta
from pathlib import Path

if __package__:
    from . import artifact_io, credential_intake, secret_provider
    from . import engagement_config as config
    from . import workspace_transaction as tx
else:
    import artifact_io
    import credential_intake
    import engagement_config as config
    import secret_provider
    import workspace_transaction as tx

LEGACY='private/credentials/credentials.jsonl'


def _sources(root,input_bytes,migrate,now):
    handles=credential_intake._open_workspace(str(root))
    try:
        hosts=credential_intake._discover_hosts(handles.workspace_fd)
        legacy=credential_intake._read_ledger(handles.credentials_fd,credential_intake._known_host_ids(hosts))
        combined=secret_provider.extend_credentials(root,list(legacy.records))
        used={item['credential_id'] for item in combined}
        keys={item['credential_key'] for item in combined}
        migrated={item['credential_id'] for item in secret_provider.metadata(root)}
        if migrate:
            records=[item for item in legacy.records if item['credential_id'] not in migrated]
        else:
            records=[]
            for candidate in credential_intake._parse_candidates(input_bytes,hosts):
                if candidate.credential_key in keys:
                    continue
                item=credential_intake._record_for(candidate,now)
                while item['credential_id'] in used:
                    now+=timedelta(microseconds=1)
                    item=credential_intake._record_for(candidate,now)
                records.append(item)
                used.add(item['credential_id'])
                keys.add(candidate.credential_key)
        return legacy.raw,records
    finally:
        handles.close()


def plan(root,*,input_bytes=b'',migrate=False,now=None):
    root=Path(root).absolute()
    secret_provider.WorkspaceVault(root)
    now=config._moment(config._stamp(now))
    legacy,records=_sources(root,input_bytes,migrate,now)
    index=secret_provider.private_file(root,secret_provider.INDEX) if (root/secret_provider.INDEX).exists() else b''
    origin=tx.digest(legacy if migrate else input_bytes)
    entries=[]
    for item in records:
        reference='vault:SEC-'+uuid.uuid5(uuid.NAMESPACE_URL,item['credential_id']+':'+item['credential_key']).hex
        entries.append({**{key:value for key,value in item.items() if key!='secret'},'vault_schema':'1.0',
                        'secret_ref':reference,'origin_sha256':origin})
    public=json.dumps(entries)
    if any(item['secret'] in public for item in records):
        raise ValueError('credential metadata contains a secret value; correct the private input before intake')
    result={'schema_version':'1.0','mode':'migration' if migrate else 'intake','workspace':str(root),
            'created_at_utc':config._stamp(now),'input_sha256':origin,'legacy_sha256':tx.digest(legacy),
            'index_sha256':tx.digest(index),'records':entries,'historical_values_retained':True,
            'checkpoint':f'private/vault/checkpoints/{origin}.jsonl' if migrate and records else None}
    result['plan_sha256']=config.digest(result)
    return result


def apply(root,reviewed,*,input_bytes=b''):
    root=Path(root).absolute()
    with tx.write_guard(root):
        current=plan(root,input_bytes=input_bytes,migrate=reviewed.get('mode')=='migration',
                     now=config._moment(reviewed['created_at_utc']))
        if current!=reviewed:
            raise ValueError('vault plan changed; preview the current source and review again')
        if not current['records']:
            return {'mode':'UNCHANGED','records':[]}
        legacy,records=_sources(root,input_bytes,current['mode']=='migration',config._moment(current['created_at_utc']))
        for relative in ('private','private/vault','private/vault/values','private/vault/checkpoints'):
            tx._private_directory(tx.safe_path(root,relative))
        transaction=tx.Transaction(root,'workspace-vault',references={'plan_sha256':current['plan_sha256']})
        if current['checkpoint']:
            checkpoint=tx.safe_path(root,current['checkpoint'])
            if checkpoint.exists():
                if secret_provider.private_file(root,current['checkpoint'])!=legacy:
                    raise ValueError('vault checkpoint differs from retained source')
            else:
                transaction.add('create',checkpoint,legacy)
        for metadata,item in zip(current['records'],records,strict=True):
            value=tx.safe_path(root,f"private/vault/values/{metadata['secret_ref'][6:]}.secret")
            transaction.add('create',value,item['secret'].encode())
            transaction.add('append',root/secret_provider.INDEX,config.encoded(metadata))
        identifier=transaction.commit()
        secret_provider.extend_credentials(root,list(credential_intake_records(root)))
        return {'mode':'APPLY','transaction_id':identifier,'plan_sha256':current['plan_sha256'],
                'records':[{'credential_id':item['credential_id'],'secret_ref':item['secret_ref']} for item in current['records']]}


def credential_intake_records(root):
    path=tx.safe_path(root,LEGACY)
    if not path.exists():
        return []
    return [json.loads(line) for line in secret_provider.private_file(root,LEGACY).splitlines()]


def store_bytes(root,input_bytes,*,now=None):
    """Internal adapter for already reviewed session-token promotion."""
    root=Path(root).absolute()
    with tx.write_guard(root):
        reviewed=plan(root,input_bytes=input_bytes,now=now)
        apply(root,reviewed,input_bytes=input_bytes)
        handles=credential_intake._open_workspace(str(root))
        try:
            candidates=credential_intake._parse_candidates(input_bytes,credential_intake._discover_hosts(handles.workspace_fd))
        finally:
            handles.close()
        combined=secret_provider.extend_credentials(root,credential_intake_records(root))
        by_key={item['credential_key']:item['credential_id'] for item in combined}
        ids=tuple(by_key[item.credential_key] for item in candidates)
        return credential_intake.CredentialStoreResult(ids,len(reviewed['records']),len(ids)-len(reviewed['records']),None)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('preview','apply','list'))
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--input-file',type=Path)
    parser.add_argument('--migrate',action='store_true')
    parser.add_argument('--plan-file',type=Path)
    args=parser.parse_args(argv)
    try:
        if args.command=='list':
            result={'provider':'workspace-vault','encrypted':False,'records':secret_provider.metadata(args.workspace)}
        else:
            raw=credential_intake._read_bounded_file(str(args.input_file)) if args.input_file else b''
            if args.command=='preview':
                if args.migrate==bool(args.input_file):
                    raise ValueError('select either --migrate or --input-file')
                result=plan(args.workspace,input_bytes=raw,migrate=args.migrate)
                if args.plan_file:
                    artifact_io.publish_file(args.plan_file,config.encoded(result))
            else:
                if not args.plan_file:
                    raise ValueError('apply requires the exact reviewed --plan-file')
                result=apply(args.workspace,config.read_input(args.plan_file),input_bytes=raw)
        print(json.dumps(result,indent=2))
        return 0
    except Exception:  # noqa: BLE001 -- never expose secret-bearing parser data or paths
        print('error: vault operation failed; verify the private input, permissions and reviewed plan; recover unfinished transactions first',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
