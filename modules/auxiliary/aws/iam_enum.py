"""
AWS IAM Enumeration Module
Enumerate IAM users, roles, policies, and permissions
"""

import json
import subprocess
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class IAMEnum(ModuleBase):
    """
    AWS IAM Enumeration module
    Enumerate users, roles, groups, policies and their permissions
    """

    def __init__(self):
        super().__init__()
        self.name = "iam_enum"
        self.description = "AWS IAM enumeration - users, roles, policies, permissions"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["aws", "iam", "cloud", "enumeration", "privilege"]
        self.references = [
            "https://hackingthe.cloud/aws/enumeration/enumerate_iam_permissions/",
            "https://docs.aws.amazon.com/cli/latest/reference/iam/",
        ]

        # Register options
        self.register_option("PROFILE", "AWS CLI profile to use", default="")
        self.register_option("ACCESS_KEY", "AWS access key ID", default="")
        self.register_option("SECRET_KEY", "AWS secret access key", default="")
        self.register_option("SESSION_TOKEN", "AWS session token", default="")
        self.register_option("ACTION", "Action: users, roles, groups, policies, attached, all",
                           default="all", choices=["users", "roles", "groups", "policies", "attached", "all"])

    def _get_env(self) -> dict:
        """Get environment with AWS credentials"""
        import os
        env = os.environ.copy()

        access_key = self.get_option("ACCESS_KEY")
        secret_key = self.get_option("SECRET_KEY")
        session_token = self.get_option("SESSION_TOKEN")

        if access_key:
            env["AWS_ACCESS_KEY_ID"] = access_key
        if secret_key:
            env["AWS_SECRET_ACCESS_KEY"] = secret_key
        if session_token:
            env["AWS_SESSION_TOKEN"] = session_token

        return env

    def _run_aws(self, args: list) -> tuple:
        """Run AWS CLI command"""
        profile = self.get_option("PROFILE")
        cmd = ["aws"] + args

        if profile:
            cmd.extend(["--profile", profile])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=60, env=self._get_env())
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            return -1, "", str(e)

    def list_users(self) -> list:
        """List IAM users"""
        self.print_status("Listing IAM users...")
        ret, stdout, stderr = self._run_aws(["iam", "list-users"])

        if ret == 0:
            data = json.loads(stdout)
            users = data.get('Users', [])
            for user in users:
                self.print_line(f"  - {user['UserName']} (Created: {user.get('CreateDate', 'N/A')})")
            return users
        else:
            self.print_error(f"Failed: {stderr}")
            return []

    def list_roles(self) -> list:
        """List IAM roles"""
        self.print_status("Listing IAM roles...")
        ret, stdout, stderr = self._run_aws(["iam", "list-roles"])

        if ret == 0:
            data = json.loads(stdout)
            roles = data.get('Roles', [])
            for role in roles:
                self.print_line(f"  - {role['RoleName']}")
                if 'AssumeRolePolicyDocument' in role:
                    policy = role['AssumeRolePolicyDocument']
                    if isinstance(policy, str):
                        policy = json.loads(policy)
                    # Show who can assume this role
                    for stmt in policy.get('Statement', []):
                        principal = stmt.get('Principal', {})
                        self.print_line(f"      Can be assumed by: {principal}")
            return roles
        else:
            self.print_error(f"Failed: {stderr}")
            return []

    def list_groups(self) -> list:
        """List IAM groups"""
        self.print_status("Listing IAM groups...")
        ret, stdout, stderr = self._run_aws(["iam", "list-groups"])

        if ret == 0:
            data = json.loads(stdout)
            groups = data.get('Groups', [])
            for group in groups:
                self.print_line(f"  - {group['GroupName']}")
            return groups
        else:
            self.print_error(f"Failed: {stderr}")
            return []

    def list_policies(self) -> list:
        """List customer managed policies"""
        self.print_status("Listing customer managed policies...")
        ret, stdout, stderr = self._run_aws(["iam", "list-policies", "--scope", "Local"])

        if ret == 0:
            data = json.loads(stdout)
            policies = data.get('Policies', [])
            for policy in policies:
                self.print_line(f"  - {policy['PolicyName']} (ARN: {policy['Arn']})")
            return policies
        else:
            self.print_error(f"Failed: {stderr}")
            return []

    def list_attached_policies(self) -> None:
        """Try to list attached user/role policies"""
        self.print_status("Checking attached policies for current identity...")

        # First get current identity
        ret, stdout, stderr = self._run_aws(["sts", "get-caller-identity"])
        if ret != 0:
            self.print_error("Could not get current identity")
            return

        identity = json.loads(stdout)
        arn = identity.get('Arn', '')

        if ':user/' in arn:
            user_name = arn.split(':user/')[1]
            self.print_status(f"Getting policies for user: {user_name}")
            ret, stdout, stderr = self._run_aws(["iam", "list-attached-user-policies",
                                                 "--user-name", user_name])
            if ret == 0:
                data = json.loads(stdout)
                for policy in data.get('AttachedPolicies', []):
                    self.print_good(f"  Attached: {policy['PolicyName']}")

            # Also get inline policies
            ret, stdout, stderr = self._run_aws(["iam", "list-user-policies",
                                                 "--user-name", user_name])
            if ret == 0:
                data = json.loads(stdout)
                for policy in data.get('PolicyNames', []):
                    self.print_good(f"  Inline: {policy}")

        elif ':assumed-role/' in arn:
            role_name = arn.split(':assumed-role/')[1].split('/')[0]
            self.print_status(f"Getting policies for role: {role_name}")
            ret, stdout, stderr = self._run_aws(["iam", "list-attached-role-policies",
                                                 "--role-name", role_name])
            if ret == 0:
                data = json.loads(stdout)
                for policy in data.get('AttachedPolicies', []):
                    self.print_good(f"  Attached: {policy['PolicyName']}")

    def run(self) -> bool:
        action = self.get_option("ACTION")

        if not find_tool("aws"):
            self.print_error("AWS CLI not found. Install with: pip install awscli")
            return False

        self.print_status("Starting IAM enumeration...")
        self.print_line()

        if action in ["users", "all"]:
            users = self.list_users()
            self.print_good(f"Found {len(users)} users")
            self.print_line()

        if action in ["roles", "all"]:
            roles = self.list_roles()
            self.print_good(f"Found {len(roles)} roles")
            self.print_line()

        if action in ["groups", "all"]:
            groups = self.list_groups()
            self.print_good(f"Found {len(groups)} groups")
            self.print_line()

        if action in ["policies", "all"]:
            policies = self.list_policies()
            self.print_good(f"Found {len(policies)} customer policies")
            self.print_line()

        if action in ["attached", "all"]:
            self.list_attached_policies()
            self.print_line()

        return True

    def check(self) -> bool:
        """Check if AWS CLI is available"""
        return find_tool("aws") is not None
