from core.module_base import ModuleBase, ModuleType, Platform
import subprocess
import re
import os


class GitSecrets(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "git_secrets"
        self.description = "Analyze git commit history for hardcoded secrets (API keys, tokens, passwords) using regex patterns"
        self.author = "HTB-Auto"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["git", "secrets", "credentials", "recon", "tokens", "api-keys"]

        self.register_option("REPO_PATH", "Path to git repository (local)", required=False, default=".")
        self.register_option("REPO_URL", "URL to clone git repository from", required=False)
        self.register_option("BRANCH", "Branch to analyze (default: all branches)", required=False, default="")
        self.register_option("DEPTH", "Number of commits to analyze (0 = all)", required=False, default="0")
        self.register_option("OUTPUT_FILE", "File to save results", required=False)

        # Regex patterns for common secrets
        self.secret_patterns = {
            # API Keys and Tokens
            "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Access Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
            "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
            "GitHub OAuth": r"gho_[A-Za-z0-9_]{36,255}",
            "GitLab Token": r"glpat-[A-Za-z0-9\-]{20,}",
            "Gitea Token": r"[a-f0-9]{40}",
            "Slack Token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
            "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
            "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,68}",
            "Discord Token": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
            "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
            "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
            "Heroku API Key": r"(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
            "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
            "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24}",
            "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
            "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
            "Twilio API Key": r"SK[0-9a-fA-F]{32}",
            "Twilio Account SID": r"AC[a-zA-Z0-9_\-]{32}",
            "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
            "Mailchimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
            "SendGrid API Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            "Azure Storage Key": r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};",
            "Azure Connection String": r"(?i)(AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{43,88}",
            "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
            "Firebase API Key": r"(?i)firebase(.{0,20})?['\"][A-Za-z0-9_-]{39}['\"]",
            
            # Private Keys
            "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
            "DSA Private Key": r"-----BEGIN DSA PRIVATE KEY-----",
            "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----",
            "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
            "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "Generic Private Key": r"-----BEGIN PRIVATE KEY-----",
            
            # Passwords and Credentials
            "Generic Password": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?",
            "Generic Secret": r"(?i)(secret|api_secret|app_secret)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?",
            "Generic Token": r"(?i)(token|auth_token|access_token|bearer)\s*[=:]\s*['\"]?[A-Za-z0-9_\-\.]{20,}['\"]?",
            "Generic API Key": r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?",
            "Basic Auth Header": r"(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]+",
            "Bearer Token Header": r"(?i)authorization:\s*bearer\s+[A-Za-z0-9_\-\.]+",
            
            # Database Credentials
            "MySQL Connection": r"mysql://[^:]+:[^@]+@[^/]+/\w+",
            "PostgreSQL Connection": r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+",
            "MongoDB Connection": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+",
            "Redis Connection": r"redis://[^:]+:[^@]+@[^/]+",
            "JDBC Connection": r"jdbc:[a-z]+://[^:]+:[^@]+@[^/]+",
            
            # Cloud Provider Credentials
            "DigitalOcean Token": r"dop_v1_[a-f0-9]{64}",
            "NPM Token": r"npm_[A-Za-z0-9]{36}",
            "PyPI Token": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}",
            "NuGet API Key": r"oy2[a-z0-9]{43}",
            
            # JWT Tokens
            "JWT Token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
            
            # SSH Keys in configs
            "SSH Key Reference": r"(?i)(id_rsa|id_dsa|id_ecdsa|id_ed25519)(?!\.pub)",
            
            # mRemoteNG (relevant for Lock box)
            "mRemoteNG Password": r"(?i)<Node.*Password=\"[^\"]+\"",
            "mRemoteNG Config": r"(?i)confCons\.xml",
            
            # Windows Specific
            "Windows Credential": r"(?i)(net use|runas).*\/user:[^\s]+\s+[^\s]+",
        }

    def run(self) -> bool:
        repo_path = self.get_option("REPO_PATH")
        repo_url = self.get_option("REPO_URL")
        branch = self.get_option("BRANCH")
        depth = int(self.get_option("DEPTH"))
        output_file = self.get_option("OUTPUT_FILE")

        # Clone repo if URL provided
        if repo_url:
            self.print_status(f"Cloning repository from {repo_url}")
            clone_dir = "/tmp/git_secrets_" + repo_url.split("/")[-1].replace(".git", "")
            try:
                subprocess.run(["rm", "-rf", clone_dir], capture_output=True)
                result = subprocess.run(
                    ["git", "clone", repo_url, clone_dir],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                if result.returncode != 0:
                    self.print_error(f"Failed to clone repository: {result.stderr}")
                    return False
                repo_path = clone_dir
                self.print_good(f"Repository cloned to {clone_dir}")
            except subprocess.TimeoutExpired:
                self.print_error("Git clone timed out")
                return False
            except Exception as e:
                self.print_error(f"Error cloning repository: {e}")
                return False

        # Verify git repository
        if not os.path.isdir(os.path.join(repo_path, ".git")):
            self.print_error(f"{repo_path} is not a git repository")
            return False

        self.print_status(f"Analyzing git repository at {repo_path}")
        
        findings = []
        
        # Get all commits
        git_log_cmd = ["git", "-C", repo_path, "log", "--all", "--pretty=format:%H"]
        if branch:
            git_log_cmd = ["git", "-C", repo_path, "log", branch, "--pretty=format:%H"]
        if depth > 0:
            git_log_cmd.extend(["-n", str(depth)])

        try:
            result = subprocess.run(git_log_cmd, capture_output=True, text=True, timeout=60)
            commits = result.stdout.strip().split("\n") if result.stdout.strip() else []
        except Exception as e:
            self.print_error(f"Error getting commits: {e}")
            return False

        self.print_status(f"Found {len(commits)} commits to analyze")

        # Analyze each commit
        for i, commit in enumerate(commits):
            if not commit:
                continue
                
            if (i + 1) % 50 == 0:
                self.print_status(f"Analyzed {i + 1}/{len(commits)} commits...")

            # Get commit details
            try:
                commit_info = subprocess.run(
                    ["git", "-C", repo_path, "log", "-1", "--pretty=format:%an|%ae|%s|%ci", commit],
                    capture_output=True, text=True, timeout=10
                )
                commit_meta = commit_info.stdout.split("|")
                author = commit_meta[0] if len(commit_meta) > 0 else "Unknown"
                email = commit_meta[1] if len(commit_meta) > 1 else "Unknown"
                message = commit_meta[2] if len(commit_meta) > 2 else "Unknown"
                date = commit_meta[3] if len(commit_meta) > 3 else "Unknown"
            except Exception:
                author = email = message = date = "Unknown"

            # Get diff for this commit
            try:
                diff_result = subprocess.run(
                    ["git", "-C", repo_path, "show", "--no-color", commit],
                    capture_output=True, text=True, timeout=30
                )
                diff_content = diff_result.stdout
            except Exception:
                continue

            # Search for secrets in diff
            for secret_type, pattern in self.secret_patterns.items():
                matches = re.finditer(pattern, diff_content, re.MULTILINE)
                for match in matches:
                    # Get context (surrounding lines)
                    start = max(0, match.start() - 100)
                    end = min(len(diff_content), match.end() + 100)
                    context = diff_content[start:end]
                    
                    # Try to get the filename
                    filename = "Unknown"
                    lines_before = diff_content[:match.start()].split("\n")
                    for line in reversed(lines_before):
                        if line.startswith("diff --git") or line.startswith("+++"):
                            if "+++" in line:
                                filename = line.replace("+++ b/", "").strip()
                            else:
                                parts = line.split(" ")
                                if len(parts) >= 3:
                                    filename = parts[2].replace("a/", "")
                            break

                    finding = {
                        "type": secret_type,
                        "commit": commit[:8],
                        "full_commit": commit,
                        "author": author,
                        "email": email,
                        "date": date,
                        "message": message,
                        "file": filename,
                        "match": match.group()[:100],  # Truncate long matches
                        "context": context.strip()
                    }
                    
                    # Avoid duplicates
                    is_duplicate = False
                    for existing in findings:
                        if existing["match"] == finding["match"] and existing["file"] == finding["file"]:
                            is_duplicate = True
                            break
                    
                    if not is_duplicate:
                        findings.append(finding)

        # Also check current working tree
        self.print_status("Checking current working tree...")
        try:
            for root, dirs, files in os.walk(repo_path):
                # Skip .git directory
                if ".git" in root:
                    continue
                    
                for file in files:
                    filepath = os.path.join(root, file)
                    rel_path = os.path.relpath(filepath, repo_path)
                    
                    # Skip binary files and large files
                    try:
                        if os.path.getsize(filepath) > 1024 * 1024:  # 1MB limit
                            continue
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                    except Exception:
                        continue

                    for secret_type, pattern in self.secret_patterns.items():
                        matches = re.finditer(pattern, content, re.MULTILINE)
                        for match in matches:
                            # Get line number
                            line_num = content[:match.start()].count("\n") + 1
                            
                            finding = {
                                "type": secret_type,
                                "commit": "WORKING_TREE",
                                "full_commit": "N/A",
                                "author": "N/A",
                                "email": "N/A",
                                "date": "Current",
                                "message": "In current working tree",
                                "file": rel_path,
                                "line": line_num,
                                "match": match.group()[:100],
                                "context": ""
                            }
                            
                            # Avoid duplicates
                            is_duplicate = False
                            for existing in findings:
                                if existing["match"] == finding["match"] and existing["file"] == finding["file"]:
                                    is_duplicate = True
                                    break
                            
                            if not is_duplicate:
                                findings.append(finding)
        except Exception as e:
            self.print_warning(f"Error scanning working tree: {e}")

        # Report findings
        if findings:
            self.print_good(f"Found {len(findings)} potential secrets!")
            self.print_status("-" * 80)
            
            output_lines = []
            
            for finding in findings:
                output = f"""
[{finding['type']}]
  Commit: {finding['commit']} ({finding['date']})
  Author: {finding['author']} <{finding['email']}>
  Message: {finding['message']}
  File: {finding['file']}
  Match: {finding['match']}
"""
                if finding.get('line'):
                    output = output.replace("File:", f"File (Line {finding['line']}):")
                    
                self.print_warning(output)
                output_lines.append(output)
                
                # Store in results
                self.add_result(
                    result_type="secret",
                    data={
                        "secret_type": finding["type"],
                        "commit": finding["full_commit"],
                        "file": finding["file"],
                        "value": finding["match"],
                        "author": finding["author"],
                        "date": finding["date"]
                    }
                )

            # Save to file if specified
            if output_file:
                try:
                    with open(output_file, "w") as f:
                        f.write(f"Git Secrets Analysis Report\n")
                        f.write(f"Repository: {repo_path}\n")
                        f.write(f"Total Findings: {len(findings)}\n")
                        f.write("=" * 80 + "\n")
                        f.write("\n".join(output_lines))
                    self.print_good(f"Results saved to {output_file}")
                except Exception as e:
                    self.print_error(f"Failed to save results: {e}")

            self.print_status("-" * 80)
            self.print_good(f"Analysis complete. Found {len(findings)} potential secrets.")
            
            # Summary by type
            type_counts = {}
            for f in findings:
                type_counts[f["type"]] = type_counts.get(f["type"], 0) + 1
            
            self.print_status("\nSummary by secret type:")
            for secret_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                self.print_status(f"  {secret_type}: {count}")
                
        else:
            self.print_status("No secrets found in the repository history.")

        return True
