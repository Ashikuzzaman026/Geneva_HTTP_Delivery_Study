import ast
import hashlib
import shutil
import sys
from pathlib import Path

def main():
    target=Path(sys.argv[1]).expanduser().resolve()
    source=Path(__file__).resolve().parent
    if not (target/'evolve.py').is_file() or not (target/'plugins/plugin_client.py').is_file():
        raise SystemExit('Target must be the existing Geneva checkout')
    paths=['geneva_healthcheck.py','plugins/filecheck/client.py','plugins/filecheck/server.py']
    for relative in paths:
        src=source/relative; dst=target/relative
        ast.parse(src.read_text())
        if dst.exists() and dst.read_bytes()!=src.read_bytes():
            raise SystemExit('Existing file differs; nothing changed: '+str(dst))
    for relative in paths:
        src=source/relative; dst=target/relative
        dst.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(str(src),str(dst))
        print('Installed: '+str(dst))
    print('Prototype installed. Original echo/http plugins and censors are unchanged.')

if __name__=='__main__': main()
