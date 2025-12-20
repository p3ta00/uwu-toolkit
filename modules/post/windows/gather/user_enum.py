from core.module_base import ModuleBase, ModuleType, Platform
import subprocess
import re


class UserEnum(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "user_enum"
        self.description = "Enumerate local users, groups, and logged-on sessions via net user/net localgroup/qwinsta"
        self.author = "HTB-Auto"
        self.module_type = ModuleType.POST
        self.platform = Platform.WINDOWS
        self.tags = ["post", "windows", "gather", "users", "groups", "sessions", "enumeration"]

        # Options for remote execution (optional - if not set, runs locally)
        self.register_option("SESSION", "Meterpreter session ID for remote execution", required=False, default="")
        self.register_option("ENUM_USERS", "Enumerate local users", required=False, default="true")
        self.register_option("ENUM_GROUPS", "Enumerate local groups", required=False, default="true")
        self.register_option("ENUM_SESSIONS", "Enumerate logged-on sessions", required=False, default="true")
        self.register_option("ENUM_ADMINS", "Enumerate administrators group members", required=False, default="true")
        self.register_option("DETAILED", "Get detailed info for each user", required=False, default="false")

    def _execute_command(self, command: str) -> tuple:
        """Execute a command and return (success, output)"""
        try:
            session = self.get_option("SESSION")
            
            if session:
                # Remote execution via session (placeholder for integration)
                self.print_status(f"Executing via session {session}: {command}")
                # This would integrate with your session management
                # For now, return empty as this needs session infrastructure
                return False, "Session-based execution not yet implemented"
            else:
                # Local execution (for post-exploitation on compromised host)
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = result.stdout + result.stderr
                return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def _parse_users(self, output: str) -> list:
        """Parse net user output to extract usernames"""
        users = []
        lines = output.split('\n')
        capture = False
        
        for line in lines:
            if '---' in line:
                capture = True
                continue
            if capture and line.strip():
                if 'The command completed' in line:
                    break
                # Users are space-separated on each line
                users.extend(line.split())
        
        return [u for u in users if u]

    def _parse_groups(self, output: str) -> list:
        """Parse net localgroup output to extract group names"""
        groups = []
        lines = output.split('\n')
        capture = False
        
        for line in lines:
            if '---' in line:
                capture = True
                continue
            if capture and line.strip():
                if 'The command completed' in line:
                    break
                # Groups start with *
                if line.strip().startswith('*'):
                    groups.append(line.strip()[1:])
        
        return groups

    def _parse_group_members(self, output: str) -> list:
        """Parse net localgroup <name> output to extract members"""
        members = []
        lines = output.split('\n')
        capture = False
        
        for line in lines:
            if '---' in line:
                capture = True
                continue
            if capture and line.strip():
                if 'The command completed' in line:
                    break
                members.append(line.strip())
        
        return members

    def _parse_sessions(self, output: str) -> list:
        """Parse qwinsta output to extract session info"""
        sessions = []
        lines = output.split('\n')
        
        for line in lines[1:]:  # Skip header
            if line.strip():
                # Parse qwinsta output format
                parts = line.split()
                if len(parts) >= 3:
                    session_info = {
                        'name': parts[0].replace('>', ''),
                        'username': parts[1] if len(parts) > 1 else '',
                        'id': parts[2] if len(parts) > 2 else '',
                        'state': parts[3] if len(parts) > 3 else ''
                    }
                    sessions.append(session_info)
        
        return sessions

    def _get_user_details(self, username: str) -> dict:
        """Get detailed information about a specific user"""
        details = {'username': username}
        
        success, output = self._execute_command(f'net user "{username}"')
        if success:
            # Parse key fields
            patterns = {
                'full_name': r'Full Name\s+(.+)',
                'comment': r'Comment\s+(.+)',
                'account_active': r'Account active\s+(.+)',
                'account_expires': r'Account expires\s+(.+)',
                'password_last_set': r'Password last set\s+(.+)',
                'password_expires': r'Password expires\s+(.+)',
                'password_changeable': r'Password changeable\s+(.+)',
                'password_required': r'Password required\s+(.+)',
                'last_logon': r'Last logon\s+(.+)',
                'local_groups': r'Local Group Memberships\s+(.+)',
                'global_groups': r'Global Group memberships\s+(.+)'
            }
            
            for key, pattern in patterns.items():
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    details[key] = match.group(1).strip()
        
        return details

    def run(self) -> bool:
        self.print_status("Starting Windows user/group/session enumeration...")
        
        enum_users = self.get_option("ENUM_USERS").lower() == "true"
        enum_groups = self.get_option("ENUM_GROUPS").lower() == "true"
        enum_sessions = self.get_option("ENUM_SESSIONS").lower() == "true"
        enum_admins = self.get_option("ENUM_ADMINS").lower() == "true"
        detailed = self.get_option("DETAILED").lower() == "true"
        
        results = {
            'users': [],
            'groups': [],
            'sessions': [],
            'administrators': [],
            'user_details': []
        }
        
        success_count = 0
        
        # Enumerate local users
        if enum_users:
            self.print_status("Enumerating local users (net user)...")
            success, output = self._execute_command("net user")
            
            if success:
                users = self._parse_users(output)
                results['users'] = users
                self.print_good(f"Found {len(users)} local users:")
                for user in users:
                    self.print_status(f"  - {user}")
                success_count += 1
                
                # Get detailed info if requested
                if detailed and users:
                    self.print_status("Gathering detailed user information...")
                    for user in users:
                        details = self._get_user_details(user)
                        results['user_details'].append(details)
                        
                        self.print_status(f"\n  User: {user}")
                        if details.get('full_name'):
                            self.print_status(f"    Full Name: {details['full_name']}")
                        if details.get('account_active'):
                            self.print_status(f"    Active: {details['account_active']}")
                        if details.get('last_logon'):
                            self.print_status(f"    Last Logon: {details['last_logon']}")
                        if details.get('local_groups'):
                            self.print_status(f"    Groups: {details['local_groups']}")
            else:
                self.print_error(f"Failed to enumerate users: {output}")
        
        # Enumerate local groups
        if enum_groups:
            self.print_status("\nEnumerating local groups (net localgroup)...")
            success, output = self._execute_command("net localgroup")
            
            if success:
                groups = self._parse_groups(output)
                results['groups'] = groups
                self.print_good(f"Found {len(groups)} local groups:")
                for group in groups:
                    self.print_status(f"  - {group}")
                success_count += 1
            else:
                self.print_error(f"Failed to enumerate groups: {output}")
        
        # Enumerate administrators group
        if enum_admins:
            self.print_status("\nEnumerating Administrators group members...")
            success, output = self._execute_command('net localgroup "Administrators"')
            
            if success:
                admins = self._parse_group_members(output)
                results['administrators'] = admins
                self.print_good(f"Found {len(admins)} administrators:")
                for admin in admins:
                    self.print_warning(f"  - {admin}")
                success_count += 1
            else:
                self.print_error(f"Failed to enumerate administrators: {output}")
        
        # Enumerate logged-on sessions
        if enum_sessions:
            self.print_status("\nEnumerating logged-on sessions (qwinsta)...")
            success, output = self._execute_command("qwinsta")
            
            if success:
                sessions = self._parse_sessions(output)
                results['sessions'] = sessions
                self.print_good(f"Found {len(sessions)} sessions:")
                for session in sessions:
                    state = session.get('state', 'Unknown')
                    username = session.get('username', 'N/A')
                    session_id = session.get('id', 'N/A')
                    session_name = session.get('name', 'N/A')
                    
                    if username and username != 'N/A':
                        self.print_status(f"  - {session_name}: {username} (ID: {session_id}, State: {state})")
                    else:
                        self.print_status(f"  - {session_name}: (ID: {session_id}, State: {state})")
                success_count += 1
            else:
                # qwinsta might not be available, try query session
                self.print_warning("qwinsta failed, trying 'query session'...")
                success, output = self._execute_command("query session")
                if success:
                    sessions = self._parse_sessions(output)
                    results['sessions'] = sessions
                    self.print_good(f"Found {len(sessions)} sessions:")
                    for session in sessions:
                        self.print_status(f"  - {session}")
                    success_count += 1
                else:
                    self.print_error(f"Failed to enumerate sessions: {output}")
        
        # Additional enumeration - Remote Desktop Users
        self.print_status("\nEnumerating Remote Desktop Users group...")
        success, output = self._execute_command('net localgroup "Remote Desktop Users"')
        if success:
            rdp_users = self._parse_group_members(output)
            if rdp_users:
                self.print_good(f"Found {len(rdp_users)} Remote Desktop Users:")
                for user in rdp_users:
                    self.print_warning(f"  - {user}")
        
        # Summary
        self.print_status("\n" + "=" * 50)
        self.print_status("ENUMERATION SUMMARY")
        self.print_status("=" * 50)
        
        if results['users']:
            self.print_good(f"Local Users: {len(results['users'])}")
        if results['groups']:
            self.print_good(f"Local Groups: {len(results['groups'])}")
        if results['administrators']:
            self.print_warning(f"Administrators: {len(results['administrators'])}")
        if results['sessions']:
            self.print_good(f"Active Sessions: {len(results['sessions'])}")
        
        # Store results for other modules
        self.results = results
        
        if success_count > 0:
            self.print_good(f"\nEnumeration completed successfully ({success_count} commands succeeded)")
            return True
        else:
            self.print_error("All enumeration commands failed")
            return False
