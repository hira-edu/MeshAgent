#!/usr/bin/env python3
"""Verify a built macOS agent exits on damaged identity without regenerating it."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent',type=Path,required=True)
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='mesh-mac-startup-') as folder:
    directory=Path(folder);agent=directory/'meshagent';shutil.copy2(args.agent.resolve(),agent)
    db=directory/'meshagent.db';script=directory/'identity.js'
    cases=[{'SelfNodeCert':'corrupt private identity'}, {'NodeID':'missing private identity'},
           {'SelfNodeTlsCert':'orphan TLS identity'}]
    for entries in cases:
        if db.exists():db.unlink()
        script.write_text('var db=require("SimpleDataStore").Create('+json.dumps(str(db))+');\n'+
            '\n'.join('db.Put('+json.dumps(key)+','+json.dumps(value)+');' for key,value in entries.items())+
            '\nprocess.exit(0);')
        subprocess.run([str(agent),str(script)],cwd=directory,check=True,capture_output=True,timeout=10)
        before=db.read_bytes()
        result=subprocess.run([str(agent)],cwd=directory,capture_output=True,text=True,timeout=10)
        assert result.returncode==1,(result.returncode,result.stdout,result.stderr)
        assert 'Existing certificate identity unavailable' in result.stdout,result.stdout
        # Startup may import configuration keys, but must leave every identity record intact.
        script.write_text('var db=require("SimpleDataStore").Create('+json.dumps(str(db))+');\n'+
            '\n'.join('if(db.Get('+json.dumps(key)+')!=='+json.dumps(value)+')throw new Error("identity changed");' for key,value in entries.items())+
            ('\nif(db.Get("SelfNodeCert")!=null)throw new Error("root regenerated");' if 'SelfNodeCert' not in entries else '')+
            '\nconsole.log("PASS: damaged identity rejected without regeneration");process.exit(0);')
        verified=subprocess.run([str(agent),str(script)],cwd=directory,capture_output=True,text=True,timeout=10)
        assert verified.returncode==0 and 'PASS:' in verified.stdout,(verified.stdout,verified.stderr)
    result=subprocess.run(['./meshagent'],cwd=directory,capture_output=True,text=True,timeout=10)
    assert result.returncode==1 and 'Existing certificate identity unavailable' in result.stdout
    alias=directory/'historical-agent';alias.symlink_to(agent)
    path_check=subprocess.run([str(alias),'-exec','console.log(process.execPath);process.exit(0);'],cwd=directory,capture_output=True,text=True,timeout=10)
    assert path_check.returncode==0 and str(alias) in path_check.stdout,(path_check.stdout,path_check.stderr)
    # Exercise production trial startup and rollback using two copies of the
    # built agent. A scripting invocation must not consume the pending trial.
    driver=directory/'apply.c'
    driver.write_text('#include "meshcore/macos_update.h"\nint main(int argc,char **argv){return argc==3 && MeshMacUpdate_Apply(argv[1],argv[2])==0?0:1;}\n')
    subprocess.run([os.environ.get('CC','clang'),'-I',str(root),str(driver),str(root/'meshcore/macos_update.c'),'-o',str(directory/'apply')],check=True)
    staged=directory/'meshagent.update';shutil.copy2(args.agent.resolve(),staged)
    old_inode=agent.stat().st_ino
    subprocess.run([str(directory/'apply'),str(agent),str(staged)],check=True)
    journal=directory/'meshagent.update-state';before_journal=journal.read_bytes()
    subprocess.run([str(agent),str(script)],cwd=directory,check=True,capture_output=True,timeout=10)
    assert journal.read_bytes()==before_journal,'script consumed update trial'
    result=subprocess.run([str(agent)],cwd=directory,capture_output=True,text=True,timeout=10)
    assert result.returncode==1 and agent.stat().st_ino==old_inode,(result.returncode,result.stdout,result.stderr)
    assert not journal.exists() and not (directory/'meshagent.update-backup').exists()
    print('PASS: built macOS identity failure exits without regeneration; scripts preserve trial; failed trial restores incumbent and releases datastore')
