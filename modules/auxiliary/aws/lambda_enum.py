"""
AWS Lambda Enumeration Module
Enumerate Lambda functions and extract environment variables/secrets
"""

import json
import subprocess
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class LambdaEnum(ModuleBase):
    """
    AWS Lambda Enumeration module
    List functions, get configurations, extract environment variables
    """

    def __init__(self):
        super().__init__()
        self.name = "lambda_enum"
        self.description = "AWS Lambda enumeration - list functions, extract env vars and secrets"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["aws", "lambda", "cloud", "enumeration", "secrets", "serverless"]
        self.references = [
            "https://hackingthe.cloud/aws/exploitation/lambda-function-theft/",
            "https://docs.aws.amazon.com/cli/latest/reference/lambda/",
        ]

        # Register options
        self.register_option("PROFILE", "AWS CLI profile to use", default="")
        self.register_option("ACCESS_KEY", "AWS access key ID", default="")
        self.register_option("SECRET_KEY", "AWS secret access key", default="")
        self.register_option("SESSION_TOKEN", "AWS session token", default="")
        self.register_option("REGION", "AWS region", default="us-east-1")
        self.register_option("FUNCTION", "Specific function name (optional)", default="")
        self.register_option("ACTION", "Action: list, config, code, all", default="all",
                           choices=["list", "config", "code", "all"])

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
        region = self.get_option("REGION")
        cmd = ["aws"] + args

        if profile:
            cmd.extend(["--profile", profile])
        if region:
            cmd.extend(["--region", region])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=60, env=self._get_env())
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            return -1, "", str(e)

    def list_functions(self) -> list:
        """List all Lambda functions"""
        self.print_status("Listing Lambda functions...")
        ret, stdout, stderr = self._run_aws(["lambda", "list-functions"])

        if ret == 0:
            data = json.loads(stdout)
            functions = data.get('Functions', [])
            for func in functions:
                self.print_line(f"  - {func['FunctionName']}")
                self.print_line(f"      Runtime: {func.get('Runtime', 'N/A')}")
                self.print_line(f"      Role: {func.get('Role', 'N/A')}")
            return functions
        else:
            self.print_error(f"Failed: {stderr}")
            return []

    def get_function_config(self, func_name: str) -> dict:
        """Get detailed function configuration including env vars"""
        self.print_status(f"Getting config for: {func_name}")
        ret, stdout, stderr = self._run_aws([
            "lambda", "get-function-configuration",
            "--function-name", func_name
        ])

        if ret == 0:
            config = json.loads(stdout)

            self.print_good(f"Function: {config.get('FunctionName')}")
            self.print_line(f"  ARN: {config.get('FunctionArn')}")
            self.print_line(f"  Runtime: {config.get('Runtime')}")
            self.print_line(f"  Handler: {config.get('Handler')}")
            self.print_line(f"  Role: {config.get('Role')}")

            # Check for environment variables (often contain secrets!)
            env_vars = config.get('Environment', {}).get('Variables', {})
            if env_vars:
                self.print_line()
                self.print_warning("Environment Variables Found:")
                for key, value in env_vars.items():
                    self.print_good(f"    {key} = {value}")
                    # Flag potential secrets
                    sensitive_keywords = ['key', 'secret', 'password', 'token', 'api', 'credential', 'auth']
                    if any(kw in key.lower() for kw in sensitive_keywords):
                        self.print_warning(f"      ^ POTENTIAL SECRET!")

            # Check VPC config
            vpc = config.get('VpcConfig', {})
            if vpc.get('SubnetIds'):
                self.print_line()
                self.print_status("VPC Configuration:")
                self.print_line(f"    Subnets: {vpc.get('SubnetIds')}")
                self.print_line(f"    Security Groups: {vpc.get('SecurityGroupIds')}")

            return config
        else:
            self.print_error(f"Failed: {stderr}")
            return {}

    def get_function_code(self, func_name: str) -> str:
        """Get function code download URL"""
        self.print_status(f"Getting code location for: {func_name}")
        ret, stdout, stderr = self._run_aws([
            "lambda", "get-function",
            "--function-name", func_name
        ])

        if ret == 0:
            data = json.loads(stdout)
            code_location = data.get('Code', {}).get('Location', '')

            if code_location:
                self.print_good(f"Code download URL:")
                self.print_line(f"  {code_location[:100]}...")
                self.print_status("Download with: curl -o function.zip '<URL>'")
            return code_location
        else:
            self.print_error(f"Failed: {stderr}")
            return ""

    def run(self) -> bool:
        action = self.get_option("ACTION")
        specific_func = self.get_option("FUNCTION")

        if not find_tool("aws"):
            self.print_error("AWS CLI not found. Install with: pip install awscli")
            return False

        self.print_status("Starting Lambda enumeration...")
        self.print_line()

        functions = []

        if action in ["list", "all"] and not specific_func:
            functions = self.list_functions()
            self.print_good(f"Found {len(functions)} functions")
            self.print_line()

        if action in ["config", "all"]:
            if specific_func:
                self.get_function_config(specific_func)
            else:
                # Get config for all functions
                if not functions:
                    ret, stdout, stderr = self._run_aws(["lambda", "list-functions"])
                    if ret == 0:
                        functions = json.loads(stdout).get('Functions', [])

                for func in functions[:10]:  # Limit to first 10
                    self.print_line()
                    self.get_function_config(func['FunctionName'])

        if action in ["code", "all"]:
            if specific_func:
                self.get_function_code(specific_func)

        return True

    def check(self) -> bool:
        """Check if AWS CLI is available"""
        return find_tool("aws") is not None
