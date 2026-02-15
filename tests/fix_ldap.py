#!/usr/bin/env python3
"""Fix LDAP settings on DC and verify."""
import subprocess, os, sys

env = {**os.environ, 'PATH': '/opt/tools/Certipy/venv/bin:/root/.local/bin:' + os.environ.get('PATH', '')}

def run(args):
    r = subprocess.run(args, capture_output=True, text=True, env=env, timeout=60)
    return r.stdout.strip(), r.stderr.strip(), r.returncode

# Query current LDAP settings
print("=== Checking LDAP settings on DC ===", flush=True)
out, err, rc = run(['atexec.py', 'westeros.local/Administrator:IronThrone2024!@10.2.10.1',
    'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" /v LdapEnforceChannelBinding'])
print(f"ChannelBinding: {out}", flush=True)

out, err, rc = run(['atexec.py', 'westeros.local/Administrator:IronThrone2024!@10.2.10.1',
    'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" /v LDAPServerIntegrity'])
print(f"Integrity: {out}", flush=True)

# Fix: set both to 0
print("\n=== Setting LDAP to permissive ===", flush=True)
out, err, rc = run(['atexec.py', 'westeros.local/Administrator:IronThrone2024!@10.2.10.1',
    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 0 /f'])
print(f"Set ChannelBinding=0: {out} (rc={rc})", flush=True)

out, err, rc = run(['atexec.py', 'westeros.local/Administrator:IronThrone2024!@10.2.10.1',
    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 0 /f'])
print(f"Set Integrity=0: {out} (rc={rc})", flush=True)

# Also set Lsa\LmCompatibilityLevel to allow NTLM
out, err, rc = run(['atexec.py', 'westeros.local/Administrator:IronThrone2024!@10.2.10.1',
    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 0 /f'])
print(f"Set LmCompatibility=0: {out} (rc={rc})", flush=True)

# Verify
print("\n=== Verifying ===", flush=True)
out, err, rc = run(['atexec.py', 'westeros.local/Administrator:IronThrone2024!@10.2.10.1',
    'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" /v LdapEnforceChannelBinding'])
print(f"ChannelBinding: {out}", flush=True)

# Test LDAP
print("\n=== Testing LDAP ===", flush=True)
out, err, rc = run(['GetADUsers.py', 'westeros.local/ned:Winter123!', '-all', '-dc-ip', '10.2.10.1'])
if 'ned' in out:
    print("LDAP: OK", flush=True)
else:
    print(f"LDAP: FAIL - {out[:200]} | {err[:200]}", flush=True)

# Test bloodyAD
out, err, rc = run(['/root/.local/bin/bloodyAD', '-u', 'ned', '-p', 'Winter123!', '-d', 'westeros.local', '--host', '10.2.10.1', 'get', 'object', 'ned', '--attr', 'sAMAccountName'])
if rc == 0:
    print(f"bloodyAD: OK - {out[:100]}", flush=True)
else:
    print(f"bloodyAD: FAIL - {err[:200]}", flush=True)
