from core.module_base import ModuleBase, ModuleType, Platform
import requests
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class GiteaCommitSecrets(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "gitea_commit_secrets"
        self.description = "Enumerate Gitea repositories and search commit diffs for hardcoded secrets, tokens, and passwords"
        self.author = "HTB-Auto"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["gitea", "git", "secrets", "enumeration", "credentials", "tokens"]

        self.register_option("RHOSTS", "Target Gitea host", required=True)
        self.register_option("RPORT", "Target Gitea port", required=True, default="3000")
        self.register_option("SSL", "Use HTTPS", required=False, default="false")
        self.register_option("TOKEN", "Gitea Personal Access Token for authenticated access", required=False, default="")
        self.register_option("USERNAME", "Target username to enumerate (leave empty for all public)", required=False, default="")
        self.register_option("REPO", "Specific repository name (leave empty for all)", required=False, default="")
        self.register_option("MAX_COMMITS", "Maximum commits to check per repository", required=False, default="100")
        self.register_option("TIMEOUT", "Request timeout in seconds", required=False, default="10")
        self.register_option("VERIFY_SSL", "Verify SSL certificates", required=False, default="false")

        # Common secret patterns
        self.secret_patterns = [
            (r'(?i)password\s*[=:]\s*["\']?([^"\'\s]+)', "Password"),
            (r'(?i)passwd\s*[=:]\s*["\']?([^"\'\s]+)', "Password"),
            (r'(?i)pwd\s*[=:]\s*["\']?([^"\'\s]+)', "Password"),
            (r'(?i)secret\s*[=:]\s*["\']?([^"\'\s]+)', "Secret"),
            (r'(?i)api[_-]?key\s*[=:]\s*["\']?([^"\'\s]+)', "API Key"),
            (r'(?i)apikey\s*[=:]\s*["\']?([^"\'\s]+)', "API Key"),
            (r'(?i)access[_-]?token\s*[=:]\s*["\']?([^"\'\s]+)', "Access Token"),
            (r'(?i)auth[_-]?token\s*[=:]\s*["\']?([^"\'\s]+)', "Auth Token"),
            (r'(?i)bearer\s+([a-zA-Z0-9_\-\.]+)', "Bearer Token"),
            (r'(?i)private[_-]?key\s*[=:]\s*["\']?([^"\'\s]+)', "Private Key"),
            (r'(?i)ssh[_-]?key\s*[=:]\s*["\']?([^"\'\s]+)', "SSH Key"),
            (r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']?([A-Z0-9]+)', "AWS Access Key"),
            (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([^"\'\s]+)', "AWS Secret Key"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'(?i)database[_-]?password\s*[=:]\s*["\']?([^"\'\s]+)', "Database Password"),
            (r'(?i)db[_-]?password\s*[=:]\s*["\']?([^"\'\s]+)', "Database Password"),
            (r'(?i)mysql[_-]?password\s*[=:]\s*["\']?([^"\'\s]+)', "MySQL Password"),
            (r'(?i)postgres[_-]?password\s*[=:]\s*["\']?([^"\'\s]+)', "Postgres Password"),
            (r'(?i)redis[_-]?password\s*[=:]\s*["\']?([^"\'\s]+)', "Redis Password"),
            (r'(?i)smtp[_-]?password\s*[=:]\s*["\']?([^"\'\s]+)', "SMTP Password"),
            (r'(?i)mail[_-]?password\s*[=:]\s*["\']?([^"\'\s]+)', "Mail Password"),
            (r'(?i)ldap[_-]?password\s*[=:]\s*["\']?([^"\'\s]+)', "LDAP Password"),
            (r'(?i)admin[_-]?password\s*[=:]\s*["\']?([^"\'\s]+)', "Admin Password"),
            (r'(?i)root[_-]?password\s*[=:]\s*["\']?([^"\'\s]+)', "Root Password"),
            (r'(?i)connection[_-]?string\s*[=:]\s*["\']?([^"\'\n]+)', "Connection String"),
            (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
            (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token"),
            (r'ghu_[a-zA-Z0-9]{36}', "GitHub User Token"),
            (r'ghs_[a-zA-Z0-9]{36}', "GitHub Server Token"),
            (r'glpat-[a-zA-Z0-9\-]{20}', "GitLab Personal Access Token"),
            (r'(?i)slack[_-]?token\s*[=:]\s*["\']?([^"\'\s]+)', "Slack Token"),
            (r'xox[baprs]-[0-9a-zA-Z\-]+', "Slack Token"),
            (r'(?i)discord[_-]?token\s*[=:]\s*["\']?([^"\'\s]+)', "Discord Token"),
            (r'(?i)telegram[_-]?token\s*[=:]\s*["\']?([^"\'\s]+)', "Telegram Token"),
            (r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)?\s*PRIVATE\s+KEY-----', "Private Key Block"),
            (r'(?i)jwt[_-]?secret\s*[=:]\s*["\']?([^"\'\s]+)', "JWT Secret"),
            (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', "JWT Token"),
        ]

    def _get_base_url(self):
        ssl = self.get_option("SSL").lower() == "true"
        protocol = "https" if ssl else "http"
        host = self.get_option("RHOSTS")
        port = self.get_option("RPORT")
        
        if (ssl and port == "443") or (not ssl and port == "80"):
            return f"{protocol}://{host}"
        return f"{protocol}://{host}:{port}"

    def _get_headers(self):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json"
        }
        token = self.get_option("TOKEN")
        if token:
            headers["Authorization"] = f"token {token}"
        return headers

    def _make_request(self, endpoint, params=None):
        base_url = self._get_base_url()
        url = f"{base_url}{endpoint}"
        timeout = int(self.get_option("TIMEOUT"))
        verify = self.get_option("VERIFY_SSL").lower() == "true"
        
        try:
            response = requests.get(
                url,
                headers=self._get_headers(),
                params=params,
                timeout=timeout,
                verify=verify
            )
            return response
        except requests.exceptions.Timeout:
            self.print_error(f"Request timeout for {url}")
            return None
        except requests.exceptions.ConnectionError as e:
            self.print_error(f"Connection error: {e}")
            return None
        except Exception as e:
            self.print_error(f"Request error: {e}")
            return None

    def _get_users(self):
        """Get list of users to enumerate"""
        username = self.get_option("USERNAME")
        if username:
            return [username]
        
        # Try to get users from explore page
        response = self._make_request("/api/v1/users/search", params={"q": "", "limit": 50})
        if response and response.status_code == 200:
            try:
                data = response.json()
                users = [u.get("username") or u.get("login") for u in data.get("data", [])]
                if users:
                    return users
            except Exception:
                pass
        
        # Try explore users page
        response = self._make_request("/explore/users")
        if response and response.status_code == 200:
            usernames = re.findall(r'href="/([^/"]+)"[^>]*class="[^"]*user-name', response.text)
            if usernames:
                return list(set(usernames))
        
        self.print_warning("Could not enumerate users, try specifying USERNAME option")
        return []

    def _get_repos(self, username):
        """Get repositories for a user"""
        repo_name = self.get_option("REPO")
        
        # API endpoint for user repos
        response = self._make_request(f"/api/v1/users/{username}/repos")
        if response and response.status_code == 200:
            try:
                repos = response.json()
                if repo_name:
                    return [r for r in repos if r.get("name") == repo_name]
                return repos
            except Exception:
                pass
        
        # Fallback: scrape user page
        response = self._make_request(f"/{username}")
        if response and response.status_code == 200:
            repo_links = re.findall(rf'href="/{re.escape(username)}/([^/"]+)"', response.text)
            repos = []
            for name in set(repo_links):
                if repo_name and name != repo_name:
                    continue
                repos.append({"name": name, "full_name": f"{username}/{name}"})
            return repos
        
        return []

    def _get_commits(self, owner, repo):
        """Get commits for a repository"""
        max_commits = int(self.get_option("MAX_COMMITS"))
        commits = []
        page = 1
        
        while len(commits) < max_commits:
            response = self._make_request(
                f"/api/v1/repos/{owner}/{repo}/commits",
                params={"page": page, "limit": 50}
            )
            
            if not response or response.status_code != 200:
                break
            
            try:
                page_commits = response.json()
                if not page_commits:
                    break
                commits.extend(page_commits)
                page += 1
            except Exception:
                break
        
        return commits[:max_commits]

    def _get_commit_diff(self, owner, repo, sha):
        """Get diff for a specific commit"""
        # Try API endpoint
        response = self._make_request(f"/api/v1/repos/{owner}/{repo}/git/commits/{sha}.diff")
        if response and response.status_code == 200:
            return response.text
        
        # Try .diff suffix on commit page
        response = self._make_request(f"/{owner}/{repo}/commit/{sha}.diff")
        if response and response.status_code == 200:
            return response.text
        
        # Try .patch suffix
        response = self._make_request(f"/{owner}/{repo}/commit/{sha}.patch")
        if response and response.status_code == 200:
            return response.text
        
        return None

    def _search_secrets(self, content, context=""):
        """Search content for secrets using regex patterns"""
        findings = []
        
        for pattern, secret_type in self.secret_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                value = match.group(0)
                # Skip very short or common false positives
                if len(value) < 4:
                    continue
                if value.lower() in ["password", "secret", "token", "key", "null", "none", "empty", "changeme", "example"]:
                    continue
                    
                findings.append({
                    "type": secret_type,
                    "value": value,
                    "context": context
                })
        
        return findings

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        port = self.get_option("RPORT")
        base_url = self._get_base_url()
        
        self.print_status(f"Targeting Gitea instance at {base_url}")
        
        # Verify Gitea is accessible
        response = self._make_request("/api/v1/version")
        if response and response.status_code == 200:
            try:
                version = response.json().get("version", "unknown")
                self.print_good(f"Gitea version: {version}")
            except Exception:
                self.print_status("Gitea instance detected")
        else:
            self.print_warning("Could not verify Gitea instance, continuing anyway...")
        
        # Check authentication
        token = self.get_option("TOKEN")
        if token:
            response = self._make_request("/api/v1/user")
            if response and response.status_code == 200:
                try:
                    user = response.json()
                    self.print_good(f"Authenticated as: {user.get('username', 'unknown')}")
                except Exception:
                    self.print_good("Token authentication successful")
            else:
                self.print_warning("Token provided but authentication may have failed")
        else:
            self.print_status("Running in unauthenticated mode (limited access)")
        
        # Get users to enumerate
        users = self._get_users()
        if not users:
            self.print_error("No users found to enumerate")
            return False
        
        self.print_status(f"Found {len(users)} user(s) to enumerate")
        
        all_findings = []
        repos_checked = 0
        commits_checked = 0
        
        for username in users:
            self.print_status(f"Enumerating user: {username}")
            
            repos = self._get_repos(username)
            if not repos:
                self.print_warning(f"No accessible repositories for {username}")
                continue
            
            self.print_status(f"Found {len(repos)} repository(ies) for {username}")
            
            for repo in repos:
                repo_name = repo.get("name", "")
                full_name = repo.get("full_name", f"{username}/{repo_name}")
                
                self.print_status(f"Checking repository: {full_name}")
                repos_checked += 1
                
                commits = self._get_commits(username, repo_name)
                if not commits:
                    self.print_warning(f"No commits accessible in {full_name}")
                    continue
                
                self.print_status(f"Analyzing {len(commits)} commit(s) in {full_name}")
                
                for commit in commits:
                    sha = commit.get("sha", "")
                    if not sha:
                        continue
                    
                    commits_checked += 1
                    diff = self._get_commit_diff(username, repo_name, sha)
                    
                    if diff:
                        context = f"{full_name}@{sha[:8]}"
                        findings = self._search_secrets(diff, context)
                        
                        for finding in findings:
                            # Check for duplicates
                            is_dup = False
                            for existing in all_findings:
                                if existing["value"] == finding["value"]:
                                    is_dup = True
                                    break
                            
                            if not is_dup:
                                all_findings.append(finding)
                                self.print_good(f"[{finding['type']}] Found in {context}")
                                self.print_good(f"  Value: {finding['value']}")
        
        # Summary
        self.print_status("-" * 50)
        self.print_status(f"Scan complete: {repos_checked} repos, {commits_checked} commits checked")
        
        if all_findings:
            self.print_good(f"Found {len(all_findings)} potential secret(s)!")
            self.print_status("")
            self.print_status("=== FINDINGS SUMMARY ===")
            for i, finding in enumerate(all_findings, 1):
                self.print_status(f"{i}. [{finding['type']}]")
                self.print_status(f"   Location: {finding['context']}")
                self.print_status(f"   Value: {finding['value']}")
                self.print_status("")
            return True
        else:
            self.print_warning("No secrets found in commit history")
            return False
