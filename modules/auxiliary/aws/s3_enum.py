"""
AWS S3 Enumeration Module
Enumerate S3 buckets, list objects, check permissions
"""

import json
import subprocess
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class S3Enum(ModuleBase):
    """
    AWS S3 Enumeration module
    Lists bucket contents, checks permissions, downloads objects
    """

    def __init__(self):
        super().__init__()
        self.name = "s3_enum"
        self.description = "AWS S3 bucket enumeration - list objects, check ACLs, download files"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["aws", "s3", "cloud", "enumeration", "bucket"]
        self.references = [
            "https://hackingthe.cloud/aws/enumeration/enumerate_s3_bucket/",
            "https://docs.aws.amazon.com/cli/latest/reference/s3/",
        ]

        # Register options
        self.register_option("BUCKET", "S3 bucket name", required=True)
        self.register_option("REGION", "AWS region", default="us-east-1")
        self.register_option("PROFILE", "AWS CLI profile to use", default="")
        self.register_option("ACCESS_KEY", "AWS access key ID (optional)", default="")
        self.register_option("SECRET_KEY", "AWS secret access key (optional)", default="")
        self.register_option("DOWNLOAD", "Download all objects (true/false)", default="false")
        self.register_option("OUTPUT_DIR", "Output directory for downloads", default="./s3_loot")
        self.register_option("ACTION", "Action: list, acl, download, all", default="list",
                           choices=["list", "acl", "download", "all"])

    def _build_aws_cmd(self, cmd_args: list) -> list:
        """Build AWS CLI command with credentials"""
        cmd = ["aws"]

        profile = self.get_option("PROFILE")
        access_key = self.get_option("ACCESS_KEY")
        secret_key = self.get_option("SECRET_KEY")
        region = self.get_option("REGION")

        if profile:
            cmd.extend(["--profile", profile])

        if region:
            cmd.extend(["--region", region])

        cmd.extend(cmd_args)
        return cmd

    def _get_env(self) -> dict:
        """Get environment with AWS credentials"""
        import os
        env = os.environ.copy()

        access_key = self.get_option("ACCESS_KEY")
        secret_key = self.get_option("SECRET_KEY")

        if access_key:
            env["AWS_ACCESS_KEY_ID"] = access_key
        if secret_key:
            env["AWS_SECRET_ACCESS_KEY"] = secret_key

        return env

    def list_objects(self, bucket: str) -> list:
        """List all objects in a bucket"""
        self.print_status(f"Listing objects in s3://{bucket}")

        cmd = self._build_aws_cmd(["s3", "ls", f"s3://{bucket}", "--recursive"])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=60, env=self._get_env())

            if result.returncode == 0:
                objects = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        self.print_line(f"  {line}")
                        parts = line.split()
                        if len(parts) >= 4:
                            objects.append({
                                'date': parts[0],
                                'time': parts[1],
                                'size': parts[2],
                                'key': ' '.join(parts[3:])
                            })
                return objects
            else:
                self.print_error(f"Failed to list bucket: {result.stderr}")
                return []
        except Exception as e:
            self.print_error(f"Error: {e}")
            return []

    def check_acl(self, bucket: str) -> dict:
        """Check bucket ACL permissions"""
        self.print_status(f"Checking ACL for s3://{bucket}")

        # Check bucket ACL
        cmd = self._build_aws_cmd(["s3api", "get-bucket-acl", "--bucket", bucket])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=30, env=self._get_env())

            if result.returncode == 0:
                acl = json.loads(result.stdout)
                self.print_good("Bucket ACL retrieved:")
                self.print_line(json.dumps(acl, indent=2))
                return acl
            else:
                self.print_warning(f"Could not get ACL: {result.stderr}")
        except Exception as e:
            self.print_error(f"Error: {e}")

        return {}

    def check_public_access(self, bucket: str) -> None:
        """Check public access block settings"""
        self.print_status(f"Checking public access settings for s3://{bucket}")

        cmd = self._build_aws_cmd(["s3api", "get-public-access-block", "--bucket", bucket])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=30, env=self._get_env())

            if result.returncode == 0:
                settings = json.loads(result.stdout)
                self.print_status("Public Access Block settings:")
                self.print_line(json.dumps(settings, indent=2))
            else:
                self.print_warning("No public access block or access denied")
        except Exception as e:
            self.print_error(f"Error: {e}")

    def download_objects(self, bucket: str, output_dir: str) -> None:
        """Download all objects from bucket"""
        import os

        self.print_status(f"Downloading s3://{bucket} to {output_dir}")
        os.makedirs(output_dir, exist_ok=True)

        cmd = self._build_aws_cmd(["s3", "sync", f"s3://{bucket}", output_dir])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=300, env=self._get_env())

            if result.returncode == 0:
                self.print_good(f"Downloaded to {output_dir}")
                if result.stdout:
                    self.print_line(result.stdout)
            else:
                self.print_error(f"Download failed: {result.stderr}")
        except Exception as e:
            self.print_error(f"Error: {e}")

    def run(self) -> bool:
        bucket = self.get_option("BUCKET")
        action = self.get_option("ACTION")
        output_dir = self.get_option("OUTPUT_DIR")

        self.print_status(f"Target bucket: {bucket}")
        self.print_line()

        if not find_tool("aws"):
            self.print_error("AWS CLI not found. Install with: pip install awscli")
            return False

        if action in ["list", "all"]:
            objects = self.list_objects(bucket)
            self.print_line()
            self.print_good(f"Found {len(objects)} objects")
            self.print_line()

        if action in ["acl", "all"]:
            self.check_acl(bucket)
            self.check_public_access(bucket)
            self.print_line()

        if action in ["download", "all"]:
            if self.get_option("DOWNLOAD").lower() == "true" or action == "download":
                self.download_objects(bucket, output_dir)

        return True

    def check(self) -> bool:
        """Check if AWS CLI is available"""
        return find_tool("aws") is not None
