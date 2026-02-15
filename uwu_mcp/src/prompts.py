"""
MCP prompt definitions for UwU Toolkit.
Guided prompts for AD pentesting workflows.
"""


def setup_prompts(mcp):
    """Register all prompts with the MCP server."""

    @mcp.prompt()
    async def ad_enumeration(target_ip: str = "", domain: str = "", username: str = "", password: str = "") -> str:
        """Guide for comprehensive Active Directory enumeration."""
        context = ""
        if target_ip:
            context += f"\nTarget DC: {target_ip}"
        if domain:
            context += f"\nDomain: {domain}"
        if username:
            context += f"\nUsername: {username}"
        if password:
            context += f"\nPassword: {password}"

        return f"""Perform comprehensive Active Directory enumeration using the available tools.
{context}

Execute the following enumeration steps in order:

1. **Domain Discovery**
   - Use `netexec` with SMB protocol to identify the domain name, DC hostname, and OS version
   - Use `ldap_search` to query root DSE for domain info

2. **User Enumeration**
   - Use `netexec` with `--users` to list all domain users
   - Use `impacket_GetUserSPNs` to find Kerberoastable accounts
   - Use `impacket_GetNPUsers` to find AS-REP Roastable accounts

3. **Group Enumeration**
   - Use `netexec` with `--groups` to list groups
   - Pay attention to: Domain Admins, Enterprise Admins, Backup Operators, Account Operators

4. **ACL Analysis**
   - Use `bloodyad` with action=get subcommand=writable to find writable objects
   - Use `bloodyad` with action=get subcommand=owned to find owned objects

5. **Certificate Services**
   - Use `certipy_find` to enumerate ADCS templates and vulnerabilities
   - Look for ESC1-ESC16 misconfigurations

6. **Delegation**
   - Use `impacket_findDelegation` to map all delegation configurations
   - Look for unconstrained, constrained, and RBCD

7. **Shares & Credentials**
   - Use `netexec` with `--shares` to enumerate SMB shares
   - Use `impacket_GetGPPPassword` to check for GPP passwords

8. **Sessions & Logons**
   - Use `netexec` with `--sessions` and `--loggedon` to find active sessions

Compile findings into a structured report with:
- User accounts and their privileges
- Identified attack paths
- Credential material found
- Recommended next steps"""

    @mcp.prompt()
    async def attack_path_planning(
        starting_user: str = "",
        goal: str = "Domain Admin",
        domain: str = "",
    ) -> str:
        """Plan an attack path from a compromised user to a target privilege level."""
        return f"""Plan attack paths from the current access level to {goal}.

Starting user: {starting_user or '[current user]'}
Domain: {domain or '[target domain]'}
Goal: {goal}

Analyze available paths:

1. **Current Privileges**
   - Check group memberships for {starting_user or 'current user'}
   - Use `bloodyad` to check writable objects and ACLs
   - Check for delegation rights with `impacket_findDelegation`

2. **Credential Attacks**
   - Kerberoast service accounts with `impacket_GetUserSPNs`
   - AS-REP Roast users with `impacket_GetNPUsers`
   - Check for cached credentials, LAPS passwords, GPP passwords

3. **ACL Abuse Paths**
   - GenericAll/GenericWrite -> modify target object
   - WriteDACL -> grant yourself permissions
   - WriteOwner -> take ownership then modify DACL
   - ForceChangePassword -> reset target password
   - AddMember -> add to privileged group
   - WriteSPN -> targeted Kerberoasting

4. **Delegation Attacks**
   - Unconstrained -> capture TGTs
   - Constrained -> S4U2Self/S4U2Proxy impersonation
   - RBCD -> configure delegation, then impersonate

5. **ADCS Attacks**
   - ESC1: Request cert with alt UPN
   - ESC4: Modify template permissions
   - ESC7: ManageCA/ManageCertificates abuse
   - ESC8: NTLM relay to web enrollment

6. **Lateral Movement**
   - Use `netexec` to test credentials across hosts
   - AdminTo -> psexec/wmiexec/smbexec
   - CanPSRemote -> WinRM
   - CanRDP -> RDP access

Prioritize paths by:
- Shortest path to {goal}
- Stealth (fewer noisy actions)
- Reliability (known working techniques)"""

    @mcp.prompt()
    async def iron_throne_walkthrough(difficulty: str = "beginner") -> str:
        """Guided walkthrough for the Iron Throne AD lab."""
        walkthroughs = {
            "beginner": """## Iron Throne Lab - Beginner Walkthrough

### Chain: The Bastard's Rise

Starting from nothing, work your way up to reading gMSA passwords.

**Step 1: AS-REP Roast**
Use `impacket_GetNPUsers` against westeros.local with a user list.
ned has DONT_REQUIRE_PREAUTH set — crack the hash.

**Step 2: Enumerate with ned's Creds**
Use `netexec` SMB to validate ned:Winter123! against 10.2.10.1
Use `netexec --shares` to find readable shares
Use `netexec --users` to enumerate users

**Step 3: Kerberoast**
Use `impacket_GetUserSPNs` with ned's creds to find SPN accounts.
8 accounts are Kerberoastable. Crack svc_maesters:Oldtown1!

**Step 4: Group Chain**
svc_maesters is in Northmen group.
bran has WriteDACL on Northmen.
bran has AddMember on Maesters group.

**Step 5: gMSA Password**
Add bran to Maesters group. Maesters can ReadGMSAPassword on svc_ravens.
Use `netexec ldap` with `-M gmsa` to read the password.""",

            "intermediate": """## Iron Throne Lab - Intermediate Walkthrough

### Chain: A Lannister Always Pays (ADCS Focus)

**Step 1: Initial Access via RDP**
missandei:Freedom1! has CanRDP on WINTERFELL.
Connect and enumerate.

**Step 2: Self-Add to Unsullied**
missandei has AddSelf on Unsullied group.
Unsullied has AdminTo WINTERFELL.
Use `bloodyad` to add missandei to Unsullied.

**Step 3: LAPS Password**
missandei (in LAPSReaders) can read WINTERFELL$ LAPS password.
Use `impacket_GetLAPSPassword` or `netexec --laps`.

**Step 4: Lateral to WINTERFELL as Admin**
Use the LAPS password with `impacket_psexec` or `netexec`.
Dump credentials — find jaime's session.

**Step 5: ADCS Exploitation**
Use jaime's creds. jaime has WriteSPN on svc_goldcloaks (targeted Kerberoast).
tyrion has SQLAdmin + WritePKIEnrollmentFlag on Citadel template (ESC4).
Modify template -> request cert as admin -> authenticate.

**Step 6: Domain Admin**
svc_wildfire has AdminTo KINGSLANDING + Unconstrained Delegation.
Or: modify Citadel template (ESC4) to allow Domain Users enrollment with ENROLLEE_SUPPLIES_SUBJECT.""",

            "advanced": """## Iron Throne Lab - Advanced Walkthrough

### Chain: Fire and Blood (Shadow Credentials + Full ADCS)

**Step 1: Kerberoast Entry**
Kerberoast svc_goldcloaks:GoldCloak1!

**Step 2: Password Reset Chain**
greyworm:Spear1234! -> ForceChangePassword on viserys
viserys has WritePKINameFlag on Valyria template

**Step 3: ESC15 (Schema v1 Template)**
Modify Valyria template name flag.
Request cert with alt subject.

**Step 4: Shadow Credentials**
euron:Silence1! has AddKeyCredentialLink on tywin.
Use `certipy_shadow` auto mode against tywin.
Get tywin's NT hash — tywin is Domain Admin.

**Step 5: Full Domain Compromise**
With DA: secretsdump for all hashes.
GoldenCert: extract CA private key.
Forge any certificate for persistent access.

### Bonus Chains:
- theon -> RBCD on KINGSLANDING$ -> DCSync
- jorah -> Constrained Delegation -> impersonate admin on KINGSLANDING
- svc_faceless -> Constrained Delegation to ldap/KINGSLANDING -> DCSync
- NTLM Relay: PetitPotam WINTERFELL -> relay to ADCS web enrollment (ESC8)""",
        }

        return walkthroughs.get(difficulty, walkthroughs["beginner"])

    @mcp.prompt()
    async def lateral_movement(
        source_host: str = "",
        target_host: str = "",
        username: str = "",
        credential_type: str = "password",
    ) -> str:
        """Guide for lateral movement between hosts."""
        return f"""Plan and execute lateral movement.

Source: {source_host or '[current host]'}
Target: {target_host or '[target host]'}
User: {username or '[current user]'}
Credential type: {credential_type}

**Pre-checks:**
1. Validate credentials with `netexec` against the target
2. Check if SMB signing is enabled (relay possible if disabled)
3. Check for local admin rights

**Movement Options (by credential type):**

For **password** credentials:
- `impacket_psexec` — creates service, most reliable
- `impacket_wmiexec` — WMI-based, semi-interactive
- `impacket_smbexec` — SMB-based, no binary on disk
- `impacket_dcomexec` — DCOM-based, alternative method
- `netexec` with `-x` for single command execution

For **hash** (pass-the-hash) credentials:
- All Impacket tools support `-hashes LM:NT` format
- `netexec` with `-H` for hash auth

For **ticket** (pass-the-ticket) credentials:
- Set `KRB5CCNAME` environment variable to ticket path
- Use `-k -no-pass` flags with Impacket tools

**Post-exploitation after landing:**
1. `whoami /all` — check privileges
2. Dump credentials: `impacket_secretsdump` with `--sam` or `--lsa`
3. Check for stored credentials (DPAPI, browser, WiFi)
4. Enumerate local shares and files
5. Look for pivot opportunities to additional hosts"""
