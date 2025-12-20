from core.module_base import ModuleBase, ModuleType, Platform
import requests
import json
import os
import subprocess


class GiteaAPI(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "gitea_api"
        self.description = "Interact with Gitea API using access tokens - list repos, clone private repos, enumerate permissions"
        self.author = "HTB-Auto"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["gitea", "git", "api", "token", "enumeration", "repository"]

        self.register_option("RHOSTS", "Target Gitea host", required=True)
        self.register_option("RPORT", "Target port", required=False, default="3000")
        self.register_option("TOKEN", "Gitea Personal Access Token", required=True)
        self.register_option("SSL", "Use HTTPS", required=False, default="false")
        self.register_option("ACTION", "Action to perform: list_repos, list_users, list_orgs, clone_repo, clone_all, user_info, repo_info, search_code", required=False, default="list_repos")
        self.register_option("REPO", "Repository name (owner/repo format) for clone_repo or repo_info", required=False, default="")
        self.register_option("CLONE_DIR", "Directory to clone repositories to", required=False, default="/tmp/gitea_repos")
        self.register_option("SEARCH_QUERY", "Search query for search_code action", required=False, default="password")

    def _get_base_url(self):
        ssl = self.get_option("SSL").lower() == "true"
        protocol = "https" if ssl else "http"
        host = self.get_option("RHOSTS")
        port = self.get_option("RPORT")
        
        if port in ["80", "443"]:
            return f"{protocol}://{host}"
        return f"{protocol}://{host}:{port}"

    def _get_headers(self):
        token = self.get_option("TOKEN")
        return {
            "Authorization": f"token {token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def _api_request(self, endpoint, method="GET", data=None):
        base_url = self._get_base_url()
        url = f"{base_url}/api/v1{endpoint}"
        headers = self._get_headers()
        
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=30, verify=False)
            elif method == "POST":
                response = requests.post(url, headers=headers, json=data, timeout=30, verify=False)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, timeout=30, verify=False)
            else:
                self.print_error(f"Unsupported HTTP method: {method}")
                return None
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 201:
                return response.json()
            elif response.status_code == 204:
                return {}
            elif response.status_code == 401:
                self.print_error("Authentication failed - invalid or expired token")
                return None
            elif response.status_code == 403:
                self.print_error("Access forbidden - insufficient permissions")
                return None
            elif response.status_code == 404:
                self.print_error(f"Resource not found: {endpoint}")
                return None
            else:
                self.print_error(f"API request failed with status {response.status_code}: {response.text}")
                return None
        except requests.exceptions.RequestException as e:
            self.print_error(f"Request failed: {str(e)}")
            return None

    def _get_current_user(self):
        return self._api_request("/user")

    def _list_repos(self):
        self.print_status("Fetching accessible repositories...")
        
        # Get current user's repos
        user_repos = self._api_request("/user/repos")
        if user_repos:
            self.print_good(f"Found {len(user_repos)} user repositories:")
            for repo in user_repos:
                private_flag = "[PRIVATE]" if repo.get("private") else "[PUBLIC]"
                self.print_status(f"  {private_flag} {repo['full_name']} - {repo.get('description', 'No description')}")
                self.print_status(f"    Clone URL: {repo.get('clone_url', 'N/A')}")
                self.print_status(f"    SSH URL: {repo.get('ssh_url', 'N/A')}")
                if repo.get("permissions"):
                    perms = repo["permissions"]
                    self.print_status(f"    Permissions: admin={perms.get('admin')}, push={perms.get('push')}, pull={perms.get('pull')}")
        
        # Get starred repos
        starred = self._api_request("/user/starred")
        if starred and len(starred) > 0:
            self.print_good(f"Found {len(starred)} starred repositories:")
            for repo in starred:
                self.print_status(f"  {repo['full_name']}")
        
        # Search for all repos accessible
        all_repos = self._api_request("/repos/search?limit=100")
        if all_repos and all_repos.get("data"):
            self.print_good(f"Found {len(all_repos['data'])} total searchable repositories:")
            for repo in all_repos["data"]:
                private_flag = "[PRIVATE]" if repo.get("private") else "[PUBLIC]"
                self.print_status(f"  {private_flag} {repo['full_name']}")
        
        return user_repos

    def _list_users(self):
        self.print_status("Enumerating users...")
        
        # Try admin endpoint first
        users = self._api_request("/admin/users")
        if users:
            self.print_good(f"Found {len(users)} users (admin access):")
            for user in users:
                admin_flag = "[ADMIN]" if user.get("is_admin") else ""
                self.print_status(f"  {user['username']} {admin_flag} - {user.get('email', 'No email')}")
            return users
        
        # Fallback to search
        self.print_status("No admin access, trying user search...")
        search_result = self._api_request("/users/search?limit=100")
        if search_result and search_result.get("data"):
            self.print_good(f"Found {len(search_result['data'])} users via search:")
            for user in search_result["data"]:
                self.print_status(f"  {user['username']} - {user.get('full_name', 'No name')}")
            return search_result["data"]
        
        return None

    def _list_orgs(self):
        self.print_status("Enumerating organizations...")
        
        # Get user's organizations
        orgs = self._api_request("/user/orgs")
        if orgs:
            self.print_good(f"Found {len(orgs)} organizations:")
            for org in orgs:
                self.print_status(f"  {org['username']} - {org.get('description', 'No description')}")
                
                # Get org repos
                org_repos = self._api_request(f"/orgs/{org['username']}/repos")
                if org_repos:
                    self.print_status(f"    Repositories ({len(org_repos)}):")
                    for repo in org_repos:
                        private_flag = "[PRIVATE]" if repo.get("private") else "[PUBLIC]"
                        self.print_status(f"      {private_flag} {repo['name']}")
                
                # Get org members
                members = self._api_request(f"/orgs/{org['username']}/members")
                if members:
                    self.print_status(f"    Members ({len(members)}):")
                    for member in members:
                        self.print_status(f"      {member['username']}")
        
        return orgs

    def _get_user_info(self):
        self.print_status("Getting current user information...")
        
        user = self._get_current_user()
        if user:
            self.print_good("Current user information:")
            self.print_status(f"  Username: {user.get('username')}")
            self.print_status(f"  Email: {user.get('email')}")
            self.print_status(f"  Full Name: {user.get('full_name')}")
            self.print_status(f"  Is Admin: {user.get('is_admin')}")
            self.print_status(f"  ID: {user.get('id')}")
            self.print_status(f"  Created: {user.get('created')}")
            
            # Get user's access tokens if admin
            if user.get("is_admin"):
                self.print_good("User has admin privileges!")
            
            # Check SSH keys
            keys = self._api_request("/user/keys")
            if keys:
                self.print_status(f"  SSH Keys ({len(keys)}):")
                for key in keys:
                    self.print_status(f"    {key.get('title')}: {key.get('key')[:50]}...")
            
            # Check GPG keys
            gpg_keys = self._api_request("/user/gpg_keys")
            if gpg_keys:
                self.print_status(f"  GPG Keys: {len(gpg_keys)}")
        
        return user

    def _get_repo_info(self, repo_name):
        self.print_status(f"Getting repository information for {repo_name}...")
        
        repo = self._api_request(f"/repos/{repo_name}")
        if repo:
            self.print_good(f"Repository: {repo['full_name']}")
            self.print_status(f"  Description: {repo.get('description', 'No description')}")
            self.print_status(f"  Private: {repo.get('private')}")
            self.print_status(f"  Fork: {repo.get('fork')}")
            self.print_status(f"  Clone URL: {repo.get('clone_url')}")
            self.print_status(f"  SSH URL: {repo.get('ssh_url')}")
            self.print_status(f"  Default Branch: {repo.get('default_branch')}")
            self.print_status(f"  Stars: {repo.get('stars_count')}")
            self.print_status(f"  Forks: {repo.get('forks_count')}")
            self.print_status(f"  Created: {repo.get('created_at')}")
            self.print_status(f"  Updated: {repo.get('updated_at')}")
            
            if repo.get("permissions"):
                perms = repo["permissions"]
                self.print_status(f"  Permissions: admin={perms.get('admin')}, push={perms.get('push')}, pull={perms.get('pull')}")
            
            # Get branches
            branches = self._api_request(f"/repos/{repo_name}/branches")
            if branches:
                self.print_status(f"  Branches ({len(branches)}):")
                for branch in branches:
                    protected = "[PROTECTED]" if branch.get("protected") else ""
                    self.print_status(f"    {branch['name']} {protected}")
            
            # Get collaborators
            collaborators = self._api_request(f"/repos/{repo_name}/collaborators")
            if collaborators:
                self.print_status(f"  Collaborators ({len(collaborators)}):")
                for collab in collaborators:
                    self.print_status(f"    {collab['username']}")
            
            # Get recent commits
            commits = self._api_request(f"/repos/{repo_name}/commits?limit=5")
            if commits:
                self.print_status(f"  Recent Commits:")
                for commit in commits:
                    sha = commit.get("sha", "")[:8]
                    msg = commit.get("commit", {}).get("message", "No message").split("\n")[0][:50]
                    author = commit.get("commit", {}).get("author", {}).get("name", "Unknown")
                    self.print_status(f"    {sha} - {msg} ({author})")
            
            # Look for interesting files
            contents = self._api_request(f"/repos/{repo_name}/contents")
            if contents:
                self.print_status("  Root Contents:")
                interesting_files = [".env", "config", "settings", ".git", "credentials", "secret", "password", "token", "key"]
                for item in contents:
                    name = item.get("name", "")
                    item_type = item.get("type", "")
                    is_interesting = any(f in name.lower() for f in interesting_files)
                    flag = "[INTERESTING]" if is_interesting else ""
                    self.print_status(f"    [{item_type}] {name} {flag}")
        
        return repo

    def _clone_repo(self, repo_name):
        self.print_status(f"Cloning repository {repo_name}...")
        
        clone_dir = self.get_option("CLONE_DIR")
        token = self.get_option("TOKEN")
        base_url = self._get_base_url()
        
        # Create clone directory
        os.makedirs(clone_dir, exist_ok=True)
        
        # Get repo info for clone URL
        repo = self._api_request(f"/repos/{repo_name}")
        if not repo:
            self.print_error(f"Could not get repository info for {repo_name}")
            return False
        
        # Construct authenticated clone URL
        clone_url = repo.get("clone_url", "")
        if clone_url:
            # Insert token into URL for authentication
            if "://" in clone_url:
                protocol, rest = clone_url.split("://", 1)
                auth_clone_url = f"{protocol}://oauth2:{token}@{rest}"
            else:
                auth_clone_url = clone_url
            
            repo_dir = os.path.join(clone_dir, repo_name.replace("/", "_"))
            
            try:
                self.print_status(f"Cloning to {repo_dir}...")
                result = subprocess.run(
                    ["git", "clone", auth_clone_url, repo_dir],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if result.returncode == 0:
                    self.print_good(f"Successfully cloned {repo_name} to {repo_dir}")
                    
                    # Look for interesting files in cloned repo
                    self._scan_repo_for_secrets(repo_dir)
                    return True
                else:
                    self.print_error(f"Clone failed: {result.stderr}")
                    return False
            except subprocess.TimeoutExpired:
                self.print_error("Clone operation timed out")
                return False
            except Exception as e:
                self.print_error(f"Clone failed: {str(e)}")
                return False
        
        return False

    def _clone_all_repos(self):
        self.print_status("Cloning all accessible repositories...")
        
        repos = self._api_request("/user/repos")
        if not repos:
            self.print_error("Could not fetch repositories")
            return False
        
        success_count = 0
        for repo in repos:
            repo_name = repo.get("full_name")
            if self._clone_repo(repo_name):
                success_count += 1
        
        self.print_good(f"Cloned {success_count}/{len(repos)} repositories")
        return success_count > 0

    def _scan_repo_for_secrets(self, repo_dir):
        self.print_status(f"Scanning {repo_dir} for sensitive information...")
        
        interesting_patterns = [
            "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
            "private_key", "privatekey", "credential", "auth", "bearer",
            ".env", "config.json", "settings.json", "credentials", ".htpasswd",
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"
        ]
        
        findings = []
        
        for root, dirs, files in os.walk(repo_dir):
            # Skip .git directory internals
            if ".git" in root.split(os.sep):
                continue
            
            for filename in files:
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, repo_dir)
                
                # Check filename
                for pattern in interesting_patterns:
                    if pattern in filename.lower():
                        findings.append(f"[FILENAME] {rel_path}")
                        break
                
                # Check file contents for small text files
                try:
                    if os.path.getsize(filepath) < 1024 * 100:  # 100KB limit
                        with open(filepath, "r", errors="ignore") as f:
                            content = f.read()
                            for pattern in interesting_patterns:
                                if pattern in content.lower():
                                    findings.append(f"[CONTENT] {rel_path} contains '{pattern}'")
                                    break
                except:
                    pass
        
        if findings:
            self.print_good(f"Found {len(findings)} potentially interesting items:")
            for finding in findings[:20]:  # Limit output
                self.print_status(f"  {finding}")
            if len(findings) > 20:
                self.print_status(f"  ... and {len(findings) - 20} more")

    def _search_code(self, query):
        self.print_status(f"Searching code for: {query}")
        
        # Get all accessible repos first
        repos = self._api_request("/user/repos")
        if not repos:
            self.print_error("Could not fetch repositories")
            return None
        
        all_results = []
        
        for repo in repos:
            repo_name = repo.get("full_name")
            # Search in repo contents
            search_result = self._api_request(f"/repos/{repo_name}/contents")
            if search_result:
                self._search_in_contents(repo_name, "", search_result, query, all_results)
        
        if all_results:
            self.print_good(f"Found {len(all_results)} matches for '{query}':")
            for result in all_results[:50]:
                self.print_status(f"  {result}")
        else:
            self.print_status(f"No matches found for '{query}'")
        
        return all_results

    def _search_in_contents(self, repo_name, path, contents, query, results, depth=0):
        if depth > 5:  # Limit recursion depth
            return
        
        for item in contents:
            item_name = item.get("name", "")
            item_path = item.get("path", "")
            item_type = item.get("type", "")
            
            if item_type == "file":
                # Check filename
                if query.lower() in item_name.lower():
                    results.append(f"[FILE] {repo_name}/{item_path}")
                
                # For small files, check content
                if item.get("size", 0) < 50000:  # 50KB limit
                    file_content = self._api_request(f"/repos/{repo_name}/contents/{item_path}")
                    if file_content and file_content.get("content"):
                        import base64
                        try:
                            decoded = base64.b64decode(file_content["content"]).decode("utf-8", errors="ignore")
                            if query.lower() in decoded.lower():
                                # Find the line containing the match
                                for i, line in enumerate(decoded.split("\n")):
                                    if query.lower() in line.lower():
                                        results.append(f"[CONTENT] {repo_name}/{item_path}:{i+1} - {line.strip()[:100]}")
                                        if len(results) > 100:
                                            return
                        except:
                            pass
            
            elif item_type == "dir":
                # Recurse into directory
                dir_contents = self._api_request(f"/repos/{repo_name}/contents/{item_path}")
                if dir_contents:
                    self._search_in_contents(repo_name, item_path, dir_contents, query, results, depth + 1)

    def run(self) -> bool:
        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        action = self.get_option("ACTION").lower()
        
        self.print_status(f"Gitea API Module - Action: {action}")
        self.print_status(f"Target: {self._get_base_url()}")
        
        # Verify token works
        user = self._get_current_user()
        if not user:
            self.print_error("Failed to authenticate with provided token")
            return False
        
        self.print_good(f"Authenticated as: {user.get('username')}")
        
        if action == "list_repos":
            result = self._list_repos()
            return result is not None
        
        elif action == "list_users":
            result = self._list_users()
            return result is not None
        
        elif action == "list_orgs":
            result = self._list_orgs()
            return result is not None
        
        elif action == "user_info":
            result = self._get_user_info()
            return result is not None
        
        elif action == "repo_info":
            repo = self.get_option("REPO")
            if not repo:
                self.print_error("REPO option required for repo_info action (format: owner/repo)")
                return False
            result = self._get_repo_info(repo)
            return result is not None
        
        elif action == "clone_repo":
            repo = self.get_option("REPO")
            if not repo:
                self.print_error("REPO option required for clone_repo action (format: owner/repo)")
                return False
            return self._clone_repo(repo)
        
        elif action == "clone_all":
            return self._clone_all_repos()
        
        elif action == "search_code":
            query = self.get_option("SEARCH_QUERY")
            result = self._search_code(query)
            return result is not None
        
        else:
            self.print_error(f"Unknown action: {action}")
            self.print_status("Available actions: list_repos, list_users, list_orgs, clone_repo, clone_all, user_info, repo_info, search_code")
            return False
