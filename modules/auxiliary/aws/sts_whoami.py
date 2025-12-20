"""
AWS STS Whoami Module
Identify current AWS identity (like sts get-caller-identity)
"""

import json
import subprocess
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class STSWhoami(ModuleBase):
    """
    AWS STS Get Caller Identity
    Identify the current AWS principal (user/role)
    """

    def __init__(self):
        super().__init__()
        self.name = "sts_whoami"
        self.description = "AWS STS get-caller-identity - identify current AWS principal"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["aws", "sts", "cloud", "enumeration", "identity"]
        self.references = [
            "https://hackingthe.cloud/aws/enumeration/whoami/",
            "https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html",
        ]

        # Register options
        self.register_option("PROFILE", "AWS CLI profile to use", default="")
        self.register_option("ACCESS_KEY", "AWS access key ID", default="")
        self.register_option("SECRET_KEY", "AWS secret access key", default="")
        self.register_option("SESSION_TOKEN", "AWS session token (for temp creds)", default="")
        self.register_option("REGION", "AWS region", default="us-east-1")

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

    def run(self) -> bool:
        profile = self.get_option("PROFILE")
        region = self.get_option("REGION")

        if not find_tool("aws"):
            self.print_error("AWS CLI not found. Install with: pip install awscli")
            return False

        self.print_status("Getting caller identity...")
        self.print_line()

        cmd = ["aws", "sts", "get-caller-identity"]

        if profile:
            cmd.extend(["--profile", profile])
        if region:
            cmd.extend(["--region", region])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=30, env=self._get_env())

            if result.returncode == 0:
                identity = json.loads(result.stdout)

                self.print_good("Identity retrieved successfully:")
                self.print_line()
                self.print_line(f"  Account:  {identity.get('Account', 'N/A')}")
                self.print_line(f"  UserId:   {identity.get('UserId', 'N/A')}")
                self.print_line(f"  ARN:      {identity.get('Arn', 'N/A')}")
                self.print_line()

                # Parse ARN for additional info
                arn = identity.get('Arn', '')
                if ':assumed-role/' in arn:
                    self.print_status("This is an assumed role (temporary credentials)")
                    role_name = arn.split(':assumed-role/')[1].split('/')[0]
                    self.print_line(f"  Role:     {role_name}")
                elif ':user/' in arn:
                    self.print_status("This is an IAM user")
                    user_name = arn.split(':user/')[1]
                    self.print_line(f"  User:     {user_name}")
                elif ':root' in arn:
                    self.print_warning("This is the ROOT account! High privilege!")

                return True
            else:
                self.print_error(f"Failed to get identity: {result.stderr}")
                return False

        except Exception as e:
            self.print_error(f"Error: {e}")
            return False

    def check(self) -> bool:
        """Check if AWS CLI is available"""
        return find_tool("aws") is not None
