from core.module_base import ModuleBase, ModuleType, Platform
import requests
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class GiteaEnum(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "gitea_enum"
        self.description = "Enumerate Gitea instances - list public repos, users, organizations, and check for exposed tokens/secrets"
        self.author = "HTB-Auto"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.MULTI
        self.tags = ["gitea", "git", "enumeration", "web", "tokens", "secrets"]

        self.register_option("RHOSTS", "Target host", required=True)
        self.register_option("RPORT", "Target port", required=True, default="3000")
        self.register_option("SSL", "Use HTTPS", required=False, default="false")
        self.register_option("TIMEOUT", "Request timeout in seconds", required=False, default="10")
        self.register_option("TOKEN", "Personal Access Token for authenticated enumeration", required=False, default="")

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        port = self.get_option("RPORT")
        use_ssl = self.get_option("SSL").lower() == "true"
        timeout = int(self.get_option("TIMEOUT"))
        token = self.get_option("TOKEN")

        protocol = "https" if use_ssl else "http"
        base_url = f"{protocol}://{target}:{port}"

        headers = {"User-Agent": "uwu-toolkit/1.0"}
        if token:
            headers["Authorization"] = f"token {token}"

        self.print_status(f"Enumerating Gitea instance at {base_url}")

        # Check if Gitea is running
        try:
            resp = requests.get(f"{base_url}/api/v1/version", headers=headers, timeout=timeout, verify=False)
            if resp.status_code == 200:
                version_info = resp.json()
                self.print_good(f"Gitea version: {version_info.get('version', 'Unknown')}")
            else:
                self.print_warning("Could not determine Gitea version via API")
        except Exception as e:
            self.print_error(f"Failed to connect to Gitea: {e}")
            return False

        # Enumerate public users
        self.print_status("Enumerating users...")
        users = self._enumerate_users(base_url, headers, timeout)

        # Enumerate public organizations
        self.print_status("Enumerating organizations...")
        orgs = self._enumerate_organizations(base_url, headers, timeout)

        # Enumerate public repositories
        self.print_status("Enumerating public repositories...")
        repos = self._enumerate_repos(base_url, headers, timeout)

        # Check repositories for exposed secrets
        if repos:
            self.print_status("Checking repositories for exposed tokens/secrets...")
            self._check_repos_for_secrets(base_url, headers, timeout, repos)

        # Try to enumerate via explore page (works without API)
        self.print_status("Checking explore page for additional information...")
        self._enumerate_explore_page(base_url, headers, timeout)

        return True

    def _enumerate_users(self, base_url, headers, timeout):
        users = []
        try:
            # Try API endpoint
            resp = requests.get(f"{base_url}/api/v1/users/search?q=&limit=100", headers=headers, timeout=timeout, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                user_list = data.get("data", [])
                if user_list:
                    self.print_good(f"Found {len(user_list)} users:")
                    for user in user_list:
                        username = user.get("username", user.get("login", "Unknown"))
                        full_name = user.get("full_name", "")
                        email = user.get("email", "")
                        is_admin = user.get("is_admin", False)
                        users.append(username)
                        admin_tag = " [ADMIN]" if is_admin else ""
                        self.print_info(f"  - {username}{admin_tag} ({full_name}) {email}")
                else:
                    self.print_warning("No users found via API")
            else:
                self.print_warning(f"Users API returned status {resp.status_code}")
        except Exception as e:
            self.print_warning(f"Failed to enumerate users: {e}")

        return users

    def _enumerate_organizations(self, base_url, headers, timeout):
        orgs = []
        try:
            resp = requests.get(f"{base_url}/api/v1/orgs?limit=100", headers=headers, timeout=timeout, verify=False)
            if resp.status_code == 200:
                org_list = resp.json()
                if org_list:
                    self.print_good(f"Found {len(org_list)} organizations:")
                    for org in org_list:
                        org_name = org.get("username", org.get("name", "Unknown"))
                        description = org.get("description", "")
                        orgs.append(org_name)
                        self.print_info(f"  - {org_name}: {description}")
                else:
                    self.print_warning("No organizations found")
            else:
                self.print_warning(f"Organizations API returned status {resp.status_code}")
        except Exception as e:
            self.print_warning(f"Failed to enumerate organizations: {e}")

        return orgs

    def _enumerate_repos(self, base_url, headers, timeout):
        repos = []
        try:
            # Try explore API
            resp = requests.get(f"{base_url}/api/v1/repos/search?q=&limit=100", headers=headers, timeout=timeout, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                repo_list = data.get("data", [])
                if repo_list:
                    self.print_good(f"Found {len(repo_list)} repositories:")
                    for repo in repo_list:
                        full_name = repo.get("full_name", "Unknown")
                        description = repo.get("description", "")
                        private = repo.get("private", False)
                        clone_url = repo.get("clone_url", "")
                        repos.append({
                            "full_name": full_name,
                            "clone_url": clone_url,
                            "owner": repo.get("owner", {}).get("username", ""),
                            "name": repo.get("name", "")
                        })
                        privacy = "[PRIVATE]" if private else "[PUBLIC]"
                        self.print_info(f"  - {full_name} {privacy}")
                        if description:
                            self.print_info(f"    Description: {description}")
                        if clone_url:
                            self.print_info(f"    Clone URL: {clone_url}")
                else:
                    self.print_warning("No repositories found via API")
            else:
                self.print_warning(f"Repos API returned status {resp.status_code}")
        except Exception as e:
            self.print_warning(f"Failed to enumerate repositories: {e}")

        return repos

    def _check_repos_for_secrets(self, base_url, headers, timeout, repos):
        secret_patterns = [
            (r'["\']?(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "API Key"),
            (r'["\']?(?:access[_-]?token|token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "Access Token"),
            (r'["\']?(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']{8,})["\']?', "Password"),
            (r'["\']?(?:secret|private[_-]?key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-/+=]{20,})["\']?', "Secret/Private Key"),
            (r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}', "GitHub Token"),
            (r'[a-zA-Z0-9]{40}', "Potential Gitea/Git Token (40 char hex)"),
            (r'Bearer\s+[a-zA-Z0-9_\-\.]+', "Bearer Token"),
            (r'Basic\s+[a-zA-Z0-9+/=]+', "Basic Auth"),
            (r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)?\s*PRIVATE\s+KEY-----', "Private Key"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        ]

        sensitive_files = [
            ".env", ".env.local", ".env.production", ".env.development",
            "config.json", "config.yaml", "config.yml", "settings.json",
            ".gitconfig", ".git-credentials", "credentials",
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
            ".htpasswd", ".htaccess", "web.config",
            "database.yml", "secrets.yml", "application.properties"
        ]

        for repo in repos:
            owner = repo.get("owner", "")
            name = repo.get("name", "")
            full_name = repo.get("full_name", "")

            if not owner or not name:
                continue

            self.print_status(f"Checking repository: {full_name}")

            # Get repository contents
            try:
                resp = requests.get(
                    f"{base_url}/api/v1/repos/{owner}/{name}/contents",
                    headers=headers, timeout=timeout, verify=False
                )
                if resp.status_code == 200:
                    contents = resp.json()
                    self._check_directory_for_secrets(base_url, headers, timeout, owner, name, contents, secret_patterns, sensitive_files, "")
            except Exception as e:
                self.print_warning(f"Failed to check repo {full_name}: {e}")

            # Check commits for secrets
            self._check_commits_for_secrets(base_url, headers, timeout, owner, name, secret_patterns)

    def _check_directory_for_secrets(self, base_url, headers, timeout, owner, name, contents, patterns, sensitive_files, path):
        if not isinstance(contents, list):
            return

        for item in contents:
            item_name = item.get("name", "")
            item_type = item.get("type", "")
            item_path = item.get("path", "")

            # Check if it's a sensitive file
            if item_type == "file":
                if item_name.lower() in [f.lower() for f in sensitive_files]:
                    self.print_good(f"  [!] Sensitive file found: {item_path}")
                    self._check_file_content(base_url, headers, timeout, owner, name, item_path, patterns)
                elif item_name.endswith(('.conf', '.config', '.ini', '.json', '.yaml', '.yml', '.xml', '.properties')):
                    self._check_file_content(base_url, headers, timeout, owner, name, item_path, patterns)

            # Recursively check directories (limit depth)
            elif item_type == "dir" and path.count("/") < 3:
                try:
                    resp = requests.get(
                        f"{base_url}/api/v1/repos/{owner}/{name}/contents/{item_path}",
                        headers=headers, timeout=timeout, verify=False
                    )
                    if resp.status_code == 200:
                        sub_contents = resp.json()
                        self._check_directory_for_secrets(base_url, headers, timeout, owner, name, sub_contents, patterns, sensitive_files, item_path)
                except:
                    pass

    def _check_file_content(self, base_url, headers, timeout, owner, name, file_path, patterns):
        try:
            resp = requests.get(
                f"{base_url}/api/v1/repos/{owner}/{name}/raw/{file_path}",
                headers=headers, timeout=timeout, verify=False
            )
            if resp.status_code == 200:
                content = resp.text
                for pattern, secret_type in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        self.print_good(f"  [!] Potential {secret_type} found in {file_path}")
                        for match in matches[:3]:  # Limit output
                            if isinstance(match, tuple):
                                match = match[0]
                            # Truncate long matches
                            display_match = match[:50] + "..." if len(match) > 50 else match
                            self.print_info(f"      -> {display_match}")
        except:
            pass

    def _check_commits_for_secrets(self, base_url, headers, timeout, owner, name, patterns):
        try:
            resp = requests.get(
                f"{base_url}/api/v1/repos/{owner}/{name}/commits?limit=20",
                headers=headers, timeout=timeout, verify=False
            )
            if resp.status_code == 200:
                commits = resp.json()
                for commit in commits:
                    sha = commit.get("sha", "")
                    message = commit.get("commit", {}).get("message", "")

                    # Check commit message for secrets
                    for pattern, secret_type in patterns:
                        if re.search(pattern, message, re.IGNORECASE):
                            self.print_good(f"  [!] Potential {secret_type} in commit message: {sha[:8]}")

                    # Get commit diff
                    try:
                        diff_resp = requests.get(
                            f"{base_url}/api/v1/repos/{owner}/{name}/git/commits/{sha}.diff",
                            headers=headers, timeout=timeout, verify=False
                        )
                        if diff_resp.status_code == 200:
                            diff_content = diff_resp.text
                            for pattern, secret_type in patterns:
                                matches = re.findall(pattern, diff_content, re.IGNORECASE)
                                if matches:
                                    self.print_good(f"  [!] Potential {secret_type} in commit {sha[:8]} diff")
                    except:
                        pass
        except:
            pass

    def _enumerate_explore_page(self, base_url, headers, timeout):
        try:
            # Check explore page for repos
            resp = requests.get(f"{base_url}/explore/repos", headers=headers, timeout=timeout, verify=False)
            if resp.status_code == 200:
                content = resp.text
                # Extract repository names from HTML
                repo_pattern = r'href="(/[^/]+/[^/]+)"[^>]*class="[^"]*name[^"]*"'
                repos = re.findall(repo_pattern, content)
                if repos:
                    self.print_info(f"Additional repos from explore page: {len(set(repos))}")

            # Check explore page for users
            resp = requests.get(f"{base_url}/explore/users", headers=headers, timeout=timeout, verify=False)
            if resp.status_code == 200:
                content = resp.text
                user_pattern = r'href="/([^/"]+)"[^>]*>\s*<img[^>]*class="[^"]*avatar[^"]*"'
                users = re.findall(user_pattern, content)
                if users:
                    self.print_info(f"Additional users from explore page: {len(set(users))}")

            # Check explore page for organizations
            resp = requests.get(f"{base_url}/explore/organizations", headers=headers, timeout=timeout, verify=False)
            if resp.status_code == 200:
                content = resp.text
                org_pattern = r'href="/org/([^/"]+)"'
                orgs = re.findall(org_pattern, content)
                if orgs:
                    self.print_info(f"Additional orgs from explore page: {len(set(orgs))}")

        except Exception as e:
            self.print_warning(f"Failed to enumerate explore page: {e}")

        # Check for admin panel access
        try:
            resp = requests.get(f"{base_url}/admin", headers=headers, timeout=timeout, verify=False, allow_redirects=False)
            if resp.status_code == 200:
                self.print_good("[!] Admin panel accessible!")
            elif resp.status_code == 302:
                self.print_info("Admin panel exists but requires authentication")
        except:
            pass
