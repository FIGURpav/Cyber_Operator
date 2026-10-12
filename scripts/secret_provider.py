"""Local workspace secret provider; values never appear in public return objects."""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Protocol

if __package__:
    from . import credential_intake, host_identity, ledger_io
    from . import workspace_transaction as tx
else:
    import credential_intake
    import host_identity
    import ledger_io
    import workspace_transaction as tx

INDEX='private/vault/credentials.jsonl'
REFERENCE=re.compile(r'vault:(SEC-[0-9a-f]{32})')


class ProviderError(ValueError):
    """A bounded failure with no secret values or input excerpts."""


class SecretProvider(Protocol):
    def resolve(self,reference: str) -> str: ...


def private_file(root,relative,maximum=16*1024*1024):
    path=tx.safe_path(Path(root).absolute(),relative)
    info=path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid()
            or stat.S_IMODE(info.st_mode)!=0o600):
        raise ProviderError('vault requires dedicated owner-only files with mode 0600')
    for parent in path.parents:
        if parent==Path(root).absolute():
            break
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise ProviderError('vault requires owner-only directories with mode 0700')
    return tx.read_file(path,maximum)


class WorkspaceVault:
    def __init__(self,root):
        self.root=Path(root).absolute()
        if os.environ.get('CYBER_SECRET_PROVIDER','workspace-vault')!='workspace-vault':
            raise ProviderError('configured secret provider is unavailable; supported backend: workspace-vault')

    def resolve(self,reference):
        if not isinstance(reference,str) or not REFERENCE.fullmatch(reference):
            raise ProviderError('invalid opaque secret reference')
        try:
            value=private_file(self.root,f'private/vault/values/{reference[6:]}.secret',16384).decode('utf-8')
            if not value or len(value)>credential_intake.MAX_SECRET_LENGTH:
                raise ProviderError('vault value has invalid size')
            return value
        except (OSError,UnicodeError,RuntimeError) as exc:
            raise ProviderError('vault value unavailable; preserve the workspace and inspect storage') from exc


def metadata(root):
    root=Path(root).absolute()
    path=tx.safe_path(root,INDEX)
    if not path.exists():
        return []
    if tx.incomplete(root):
        raise ProviderError('vault has an unfinished transaction; recover before reading')
    raw=private_file(root,INDEX)
    if raw and not raw.endswith(b'\n'):
        raise ProviderError('vault metadata has an incomplete record')
    values=[]
    seen=set()
    expected=set(credential_intake.CREDENTIAL_FIELDS)-{'secret'}|{'vault_schema','secret_ref','origin_sha256'}
    for line in raw.splitlines():
        item=ledger_io.loads_json(line)
        if (not isinstance(item,dict) or set(item)!=expected or item['vault_schema']!='1.0'
                or not isinstance(item['secret_ref'],str) or not REFERENCE.fullmatch(item['secret_ref'])
                or not isinstance(item['origin_sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',item['origin_sha256'])
                or not isinstance(item['credential_id'],str) or not credential_intake.CREDENTIAL_ID_RE.fullmatch(item['credential_id'])
                or item['credential_id'] in seen):
            raise ProviderError('vault metadata has invalid fields or duplicate identities')
        seen.add(item['credential_id'])
        values.append(item)
    return values


def extend_credentials(root,legacy):
    """Internal compatibility boundary; resolved values must not be serialized."""
    entries=metadata(root)
    if not entries:
        return legacy
    provider=WorkspaceVault(root)
    known=host_identity.known_host_ids(Path(root))
    result={item['credential_id']:item for item in legacy}
    for item in entries:
        record={field:item[field] for field in credential_intake.CREDENTIAL_FIELDS if field!='secret'}
        record['secret']=provider.resolve(item['secret_ref'])
        try:
            credential_intake._validate_ledger_record(record,1,known)
        except (credential_intake.CredentialIntakeError,KeyError,TypeError) as exc:
            raise ProviderError('vault credential metadata does not match its value or host') from exc
        identifier=record['credential_id']
        if identifier in result and result[identifier]!=record:
            raise ProviderError('retained private credential differs from the vault copy')
        result[identifier]=record
    return list(result.values())
