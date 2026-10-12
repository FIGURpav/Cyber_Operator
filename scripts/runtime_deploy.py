"""Local Linux install, upgrade, verification and recoverable rollback."""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import shlex
import stat
import subprocess
import sys
import tomllib
import uuid
import zipfile
from pathlib import Path

if __package__:
    from . import release_check
else:
    import release_check

MAX_ARCHIVE=64*1024*1024
SCHEMAS={'engagement':'1.0','configuration_events':['1.0','1.1'],'assessment_events':'1.0',
         'report':['2.0','2.1','3.0'],'vault':'1.0','workspace_transaction':'1.0','checkpoint':'1.2'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def safe(path):
    path=Path(path).expanduser().absolute()
    if '..' in path.parts or any(part.is_symlink() for part in (path,*path.parents)):
        raise ValueError('deployment paths must be canonical and contain no symlinks')
    if path==Path(path.anchor):
        raise ValueError('deployment cannot use a filesystem root')
    return path


def write(path,raw,mode=0o600):
    temporary=path.with_name('.'+path.name+'.'+uuid.uuid4().hex)
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
    try:
        with os.fdopen(descriptor,'wb') as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary,path)
    finally:
        temporary.unlink(missing_ok=True)


def inventory(root):
    return [{'path':path.relative_to(root).as_posix(),'sha256':digest(path.read_bytes()),'bytes':path.stat().st_size}
            for path in release_check.release_files(root) if path.name!='RELEASE_INVENTORY.json']


def archive_contents(path):
    path=safe(path)
    if path.stat().st_size>MAX_ARCHIVE:
        raise ValueError('release archive exceeds its limit')
    raw=path.read_bytes()
    contents={}
    with zipfile.ZipFile(path) as archive:
        if len(archive.infolist())>5000 or sum(item.file_size for item in archive.infolist())>MAX_ARCHIVE:
            raise ValueError('release expansion exceeds its limit')
        for item in archive.infolist():
            name=item.filename
            relative=name.removeprefix('Cyber-Operator/')
            if (not name.startswith('Cyber-Operator/') or name in contents or not relative
                    or Path(relative).is_absolute() or '..' in Path(relative).parts or '\\' in relative
                    or Path(relative).as_posix()!=relative or item.is_dir()
                    or stat.S_ISLNK(item.external_attr>>16)):
                raise ValueError('release contains an invalid path or duplicate member')
            if relative in contents:
                raise ValueError('release contains a duplicate member')
            contents[relative]=archive.read(item)
    manifest=json.loads(contents.pop('RELEASE_INVENTORY.json'))
    actual=[{'path':name,'sha256':digest(data),'bytes':len(data)} for name,data in sorted(contents.items())]
    if manifest!=actual:
        raise ValueError('release inventory does not match archive contents')
    version=tomllib.loads(contents['pyproject.toml'].decode())['project']['version']
    return {'sha256':digest(raw),'version':version,'inventory':actual},contents


def preview(archive,destination,state_dir,bin_dir,python,config_path,*,baseline=None):
    destination,state_dir,bin_dir,config_path=map(safe,(destination,state_dir,bin_dir,config_path))
    if any(left==right or left in right.parents or right in left.parents
           for left,right in ((destination,state_dir),(destination,bin_dir),(destination,config_path))):
        raise ValueError('runtime source, deployment state, wrappers and configuration must be separate')
    release,_=archive_contents(archive)
    before=inventory(destination) if destination.exists() else []
    if before:
        stored=destination/'RELEASE_INVENTORY.json'
        expected=json.loads(Path(baseline).read_text()) if baseline else json.loads(stored.read_text()) if stored.exists() else None
        if before!=expected:
            raise ValueError('installed source differs from the approved baseline; preserve and review differences')
    elif destination.exists():
        raise ValueError('existing empty or unmanaged destination cannot be adopted silently')
    check=subprocess.run([str(python),'-c','import sys; print(".".join(map(str,sys.version_info[:3])))'],capture_output=True,text=True,check=True)
    if tuple(map(int,check.stdout.strip().split('.'))) < (3,13,0):
        raise ValueError('runtime requires Python 3.13 or newer')
    wrappers={}
    for name in (item['path'].split('/')[-1] for item in release['inventory'] if item['path'].startswith('scripts/cyber-')):
        path=safe(bin_dir/name)
        wrappers[name]=digest(path.read_bytes()) if path.exists() else None
    result={'schema_version':'1.0','archive':str(safe(archive)),'release':release,'destination':str(destination),
            'state_dir':str(state_dir),'bin_dir':str(bin_dir),'python':str(Path(python).absolute()),'python_version':check.stdout.strip(),
            'config_path':str(config_path),'installed_inventory':before,'wrappers_before':wrappers,
            'schemas':SCHEMAS,'workspace_migration':'none','private_data_changes':'none',
            'rollback':'Use cyber-deploy rollback --receipt <deployment receipt directory>; newer workspace schemas still need their matching runtime.'}
    result['plan_sha256']=digest(encoded(result))
    return result


@contextlib.contextmanager
def deployment_lock(state_dir):
    state_dir=safe(state_dir)
    state_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
    descriptor=os.open(state_dir/'.deployment.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(descriptor,fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def wrapper(plan,name,environment):
    return ('#!/bin/sh\nset -eu\numask 077\n'
            +'export CYBER_CONFIG="${CYBER_CONFIG:-'+str(plan['config_path']).replace('\\','\\\\').replace('"','\\"').replace('$','\\$').replace('`','\\`')+'}"\n'
            +'export PATH='+shlex.quote(str(environment/'bin'))+':"$PATH"\n'
            +'exec '+shlex.quote(str(Path(plan['destination'])/'scripts'/name))+' "$@"\n').encode()


def _after_step(_step):
    """Synthetic interruption seam."""


def install(plan):
    state_dir=safe(plan['state_dir'])
    with deployment_lock(state_dir):
        # Revalidate the complete installed source and each wrapper at apply time.
        contents_info,contents=archive_contents(plan['archive'])
        destination=safe(plan['destination'])
        before=inventory(destination) if destination.exists() else []
        if contents_info!=plan['release'] or before!=plan['installed_inventory']:
            raise ValueError('source changed after deployment preview')
        if digest(encoded({key:value for key,value in plan.items() if key!='plan_sha256'}))!=plan['plan_sha256']:
            raise ValueError('deployment plan hash mismatch')
        bin_dir=safe(plan['bin_dir'])
        for name,expected in plan['wrappers_before'].items():
            path=safe(bin_dir/name)
            if (digest(path.read_bytes()) if path.exists() else None)!=expected:
                raise ValueError('installed wrapper changed after preview')
        jobs=state_dir/'deployments'
        jobs.mkdir(mode=0o700,exist_ok=True)
        if any(not (item/'COMMITTED.json').exists() and not (item/'ROLLED_BACK.json').exists() for item in jobs.iterdir()):
            raise ValueError('unfinished deployment; recover or roll it back first')
        identifier='DEP-'+uuid.uuid4().hex
        directory=jobs/identifier
        directory.mkdir(mode=0o700)
        stage=directory/'staged-source'
        environment=directory/'environment'
        receipt={**plan,'deployment_id':identifier,'environment':str(environment),'stage':str(stage),
                 'backup':str(directory/'source-before')}
        write(directory/'plan.json',encoded(receipt))
        stage.mkdir(mode=0o700)
        subprocess.run([plan['python'],'-m','venv','--without-pip',str(environment)],check=True,capture_output=True)
        for relative,raw in contents.items():
            path=stage/relative
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            write(path,raw,0o755 if relative.startswith('scripts/cyber-') else 0o644)
        write(stage/'RELEASE_INVENTORY.json',encoded(plan['release']['inventory']),0o644)
        if inventory(stage)!=plan['release']['inventory']:
            raise ValueError('staged release validation failed')
        backup_wrappers=directory/'wrappers-before'
        backup_wrappers.mkdir(mode=0o700)
        for name,expected in plan['wrappers_before'].items():
            if expected is not None:
                write(backup_wrappers/name,(bin_dir/name).read_bytes(),0o755)
        write(directory/'PREPARED.json',encoded({'deployment_id':identifier,'plan_sha256':plan['plan_sha256']}))
        _after_step('prepared')
        return _finish(directory,receipt)


def _finish(directory,receipt):
    if not (directory/'PREPARED.json').exists():
        raise ValueError('deployment preparation was interrupted; roll back this receipt and prepare a fresh deployment')
    target=safe(receipt['destination'])
    stage=safe(receipt['stage'])
    backup=safe(receipt['backup'])
    if target.exists() and inventory(target)!=receipt['release']['inventory']:
        if inventory(target)!=receipt['installed_inventory'] or backup.exists():
            raise ValueError('deployment destination conflicts with the retained plan')
        os.replace(target,backup)
        _after_step('old-source-retained')
    if not target.exists():
        if inventory(stage)!=receipt['release']['inventory']:
            raise ValueError('staged release changed')
        target.parent.mkdir(parents=True,exist_ok=True)
        os.replace(stage,target)
        _after_step('new-source-active')
    bin_dir=safe(receipt['bin_dir'])
    bin_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
    for name,expected in receipt['wrappers_before'].items():
        path=safe(bin_dir/name)
        raw=wrapper(receipt,name,Path(receipt['environment']))
        actual=path.read_bytes() if path.exists() else None
        if actual!=raw and (digest(actual) if actual is not None else None)!=expected:
            raise ValueError('wrapper differs from both old and prepared versions')
        write(path,raw,0o755)
    _after_step('wrappers-active')
    write(directory/'COMMITTED.json',encoded({'deployment_id':receipt['deployment_id'],'release_sha256':receipt['release']['sha256']}))
    return {'status':'installed','version':receipt['release']['version'],'receipt':str(directory),'rollback_source':str(backup)}


def recover(directory,*,rollback=False):
    directory=safe(directory)
    receipt=json.loads((directory/'plan.json').read_text())
    original={key:value for key,value in receipt.items() if key not in {'deployment_id','environment','stage','backup'}}
    if digest(encoded({key:value for key,value in original.items() if key!='plan_sha256'}))!=original['plan_sha256']:
        raise ValueError('retained deployment plan hash mismatch')
    if directory!=safe(receipt['state_dir'])/'deployments'/receipt['deployment_id']:
        raise ValueError('deployment receipt location mismatch')
    if (safe(receipt['stage'])!=directory/'staged-source' or safe(receipt['backup'])!=directory/'source-before'
            or safe(receipt['environment'])!=directory/'environment'):
        raise ValueError('retained deployment paths do not match the receipt')
    with deployment_lock(receipt['state_dir']):
        if rollback and not (directory/'PREPARED.json').exists():
            target=safe(receipt['destination'])
            if (inventory(target) if target.exists() else [])!=receipt['installed_inventory']:
                raise ValueError('runtime changed during interrupted preparation; preserve for manual review')
            for name,expected in receipt['wrappers_before'].items():
                path=safe(Path(receipt['bin_dir'])/name)
                if (digest(path.read_bytes()) if path.exists() else None)!=expected:
                    raise ValueError('wrapper changed during interrupted preparation')
            write(directory/'ROLLED_BACK.json',encoded({'deployment_id':receipt['deployment_id'],'preparation_only':True}))
            return {'status':'rolled-back','receipt':str(directory),'source_unchanged':True}
        if not rollback:
            if (directory/'ROLLED_BACK.json').exists():
                raise ValueError('rolled-back deployment cannot be resumed')
            return _finish(directory,receipt)
        target=safe(receipt['destination'])
        backup=safe(receipt['backup'])
        if target.exists() and inventory(target)==receipt['release']['inventory']:
            os.replace(target,directory/'rolled-back-source')
        elif target.exists() and inventory(target)!=receipt['installed_inventory']:
            raise ValueError('current runtime changed; refusing rollback')
        if backup.exists():
            if target.exists() or inventory(backup)!=receipt['installed_inventory']:
                raise ValueError('rollback source conflicts with current installation')
            os.replace(backup,target)
        for name,expected in receipt['wrappers_before'].items():
            path=safe(Path(receipt['bin_dir'])/name)
            prepared=wrapper(receipt,name,Path(receipt['environment']))
            raw=path.read_bytes() if path.exists() else None
            if raw!=prepared and (digest(raw) if raw is not None else None)!=expected:
                raise ValueError('wrapper changed; refusing rollback')
            if expected is None:
                path.unlink(missing_ok=True)
            else:
                original=(directory/'wrappers-before'/name).read_bytes()
                if digest(original)!=expected:
                    raise ValueError('wrapper backup changed')
                write(path,original,0o755)
        write(directory/'ROLLED_BACK.json',encoded({'deployment_id':receipt['deployment_id']}))
        return {'status':'rolled-back','receipt':str(directory),'retained_new_source':str(directory/'rolled-back-source')}


def verify(destination,receipt=None):
    destination=safe(destination)
    expected=json.loads((destination/'RELEASE_INVENTORY.json').read_text())
    if inventory(destination)!=expected:
        raise ValueError('installed source differs from its release inventory')
    if receipt:
        value=json.loads((safe(receipt)/'plan.json').read_text())
        if destination!=Path(value['destination']) or expected!=value['release']['inventory']:
            raise ValueError('deployment receipt differs from installed source')
        for name in value['wrappers_before']:
            if (Path(value['bin_dir'])/name).read_bytes()!=wrapper(value,name,Path(value['environment'])):
                raise ValueError('installed wrapper differs from deployment receipt')
    return {'verified':True,'files':len(expected),'schemas':SCHEMAS,'workspaces_modified':False}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('preview','apply','verify','recover','rollback'))
    for name in ('archive','destination','state-dir','bin-dir','python','config-path','baseline','plan-file','receipt'):
        parser.add_argument('--'+name,type=Path)
    args=parser.parse_args(argv)
    try:
        if args.command=='preview':
            if not all((args.archive,args.destination,args.state_dir,args.bin_dir,args.python,args.config_path,args.plan_file)):
                raise ValueError('preview requires all deployment paths, Python executable and a new plan file')
            result=preview(args.archive,args.destination,args.state_dir,args.bin_dir,args.python,args.config_path,baseline=args.baseline)
            if args.plan_file.exists():
                raise ValueError('plan file already exists')
            write(args.plan_file,encoded(result))
        elif args.command=='apply':
            result=install(json.loads(args.plan_file.read_text()))
        elif args.command=='verify':
            result=verify(args.destination,args.receipt)
        else:
            result=recover(args.receipt,rollback=args.command=='rollback')
        print(json.dumps(result,indent=2))
        return 0
    except (ValueError,OSError,RuntimeError,subprocess.SubprocessError,KeyError,TypeError,AttributeError) as exc:
        print(f'error: {exc}',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
