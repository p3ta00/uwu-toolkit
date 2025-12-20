from core.module_base import ModuleBase, ModuleType, Platform
import os
import re


class CICDDetect(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "cicd_detect"
        self.description = "Identify CI/CD pipelines from repository configs (.github/workflows, .gitlab-ci.yml, Jenkinsfile, etc.)"
        self.author = "HTB-Auto"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.MULTI
        self.tags = ["cicd", "gitea", "github", "gitlab", "jenkins", "enumeration", "recon"]

        self.register_option("REPO_PATH", "Local path to cloned repository", required=False)
        self.register_option("REPO_URL", "URL to repository (Gitea/GitHub/GitLab)", required=False)
        self.register_option("ACCESS_TOKEN", "Personal Access Token for private repos", required=False)
        self.register_option("RHOSTS", "Target host running Git service", required=False)
        self.register_option("RPORT", "Target port (default: 3000 for Gitea)", required=False, default="3000")

        self.cicd_indicators = {
            "github_actions": {
                "paths": [".github/workflows/", ".github/workflows/*.yml", ".github/workflows/*.yaml"],
                "description": "GitHub Actions workflows"
            },
            "gitlab_ci": {
                "paths": [".gitlab-ci.yml", ".gitlab-ci.yaml"],
                "description": "GitLab CI/CD pipeline"
            },
            "jenkins": {
                "paths": ["Jenkinsfile", "jenkins/", ".jenkins/"],
                "description": "Jenkins pipeline"
            },
            "azure_devops": {
                "paths": ["azure-pipelines.yml", "azure-pipelines.yaml", ".azure-pipelines/"],
                "description": "Azure DevOps pipeline"
            },
            "circleci": {
                "paths": [".circleci/config.yml", ".circleci/config.yaml"],
                "description": "CircleCI pipeline"
            },
            "travis": {
                "paths": [".travis.yml", ".travis.yaml"],
                "description": "Travis CI pipeline"
            },
            "drone": {
                "paths": [".drone.yml", ".drone.yaml"],
                "description": "Drone CI pipeline"
            },
            "bitbucket": {
                "paths": ["bitbucket-pipelines.yml"],
                "description": "Bitbucket Pipelines"
            },
            "teamcity": {
                "paths": [".teamcity/"],
                "description": "TeamCity configuration"
            },
            "buildkite": {
                "paths": [".buildkite/pipeline.yml", ".buildkite/pipeline.yaml", "buildkite.yml"],
                "description": "Buildkite pipeline"
            },
            "woodpecker": {
                "paths": [".woodpecker.yml", ".woodpecker/"],
                "description": "Woodpecker CI pipeline"
            },
            "tekton": {
                "paths": [".tekton/", "tekton/"],
                "description": "Tekton pipeline"
            },
            "argo": {
                "paths": [".argo/", "argo-workflows/"],
                "description": "Argo Workflows"
            }
        }

        self.readme_patterns = [
            r"!\[.*(build|ci|pipeline|workflow|status).*\]\((https?://[^\)]+)\)",
            r"(travis-ci\.org|circleci\.com|github\.com/.*/(actions|workflows)|gitlab\.com/.*/-/pipelines)",
            r"(jenkins|bamboo|teamcity|azure\s*devops|bitbucket\s*pipelines)",
            r"(npm\s+run\s+build|yarn\s+build|make\s+build|docker\s+build)",
            r"(deploy|deployment|ci/cd|continuous\s+integration|continuous\s+delivery)"
        ]

    def run(self) -> bool:
        repo_path = self.get_option("REPO_PATH")
        repo_url = self.get_option("REPO_URL")
        access_token = self.get_option("ACCESS_TOKEN")
        rhosts = self.get_option("RHOSTS")
        rport = self.get_option("RPORT")

        found_pipelines = []
        secrets_hints = []

        if repo_path and os.path.isdir(repo_path):
            self.print_status(f"Scanning local repository: {repo_path}")
            found_pipelines, secrets_hints = self._scan_local_repo(repo_path)
        elif repo_url:
            self.print_status(f"Scanning remote repository: {repo_url}")
            found_pipelines, secrets_hints = self._scan_remote_repo(repo_url, access_token)
        elif rhosts:
            self.print_status(f"Enumerating Git service on {rhosts}:{rport}")
            found_pipelines, secrets_hints = self._enumerate_git_service(rhosts, rport, access_token)
        else:
            self.print_error("Must specify REPO_PATH, REPO_URL, or RHOSTS")
            return False

        if found_pipelines:
            self.print_good(f"Found {len(found_pipelines)} CI/CD pipeline(s):")
            for pipeline in found_pipelines:
                self.print_success(f"  [+] {pipeline['type']}: {pipeline['path']}")
                if pipeline.get('details'):
                    for detail in pipeline['details']:
                        self.print_status(f"      - {detail}")

        if secrets_hints:
            self.print_warning("Potential secrets/credentials indicators found:")
            for hint in secrets_hints:
                self.print_warning(f"  [!] {hint}")

        if not found_pipelines:
            self.print_status("No CI/CD pipelines detected")
            return True

        return True

    def _scan_local_repo(self, repo_path: str) -> tuple:
        found_pipelines = []
        secrets_hints = []

        for cicd_name, cicd_info in self.cicd_indicators.items():
            for path_pattern in cicd_info["paths"]:
                full_path = os.path.join(repo_path, path_pattern.rstrip("*"))
                
                if "*" in path_pattern:
                    dir_path = os.path.dirname(full_path)
                    if os.path.isdir(dir_path):
                        for f in os.listdir(dir_path):
                            file_path = os.path.join(dir_path, f)
                            if os.path.isfile(file_path):
                                pipeline_info = {
                                    "type": cicd_info["description"],
                                    "path": os.path.join(path_pattern.rstrip("*"), f),
                                    "details": []
                                }
                                details, secrets = self._analyze_pipeline_file(file_path)
                                pipeline_info["details"] = details
                                secrets_hints.extend(secrets)
                                found_pipelines.append(pipeline_info)
                elif os.path.exists(full_path):
                    pipeline_info = {
                        "type": cicd_info["description"],
                        "path": path_pattern,
                        "details": []
                    }
                    if os.path.isfile(full_path):
                        details, secrets = self._analyze_pipeline_file(full_path)
                        pipeline_info["details"] = details
                        secrets_hints.extend(secrets)
                    found_pipelines.append(pipeline_info)

        readme_files = ["README.md", "README.rst", "README.txt", "readme.md"]
        for readme in readme_files:
            readme_path = os.path.join(repo_path, readme)
            if os.path.isfile(readme_path):
                hints = self._analyze_readme(readme_path)
                if hints:
                    found_pipelines.append({
                        "type": "README hints",
                        "path": readme,
                        "details": hints
                    })

        return found_pipelines, secrets_hints

    def _analyze_pipeline_file(self, file_path: str) -> tuple:
        details = []
        secrets_hints = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            secret_patterns = [
                (r'\$\{\{\s*secrets\.([A-Z_]+)\s*\}\}', "GitHub secret reference"),
                (r'\$([A-Z_]+_TOKEN)', "Token environment variable"),
                (r'\$([A-Z_]+_KEY)', "Key environment variable"),
                (r'\$([A-Z_]+_PASSWORD)', "Password environment variable"),
                (r'(api[_-]?key|apikey)\s*[:=]', "API key reference"),
                (r'(access[_-]?token)\s*[:=]', "Access token reference"),
                (r'(private[_-]?key)\s*[:=]', "Private key reference"),
                (r'(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)', "AWS credentials"),
                (r'(DOCKER_PASSWORD|DOCKER_USERNAME)', "Docker credentials"),
                (r'(NPM_TOKEN|PYPI_TOKEN|NUGET_API_KEY)', "Package registry token"),
            ]

            for pattern, desc in secret_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    for match in matches:
                        secrets_hints.append(f"{desc}: {match}")

            if "deploy" in content.lower():
                details.append("Contains deployment steps")
            if "docker" in content.lower():
                details.append("Uses Docker")
            if "ssh" in content.lower() or "scp" in content.lower():
                details.append("Uses SSH/SCP (potential lateral movement)")
            if "kubectl" in content.lower() or "kubernetes" in content.lower():
                details.append("Kubernetes deployment")
            if "terraform" in content.lower():
                details.append("Terraform infrastructure")
            if "ansible" in content.lower():
                details.append("Ansible automation")
            if "aws" in content.lower() or "s3" in content.lower():
                details.append("AWS integration")
            if "azure" in content.lower():
                details.append("Azure integration")
            if "gcp" in content.lower() or "gcloud" in content.lower():
                details.append("GCP integration")

            trigger_patterns = [
                (r'on:\s*\n\s*push:', "Triggered on push"),
                (r'on:\s*\n\s*pull_request:', "Triggered on PR"),
                (r'schedule:', "Scheduled execution"),
                (r'workflow_dispatch:', "Manual trigger available"),
            ]
            for pattern, desc in trigger_patterns:
                if re.search(pattern, content):
                    details.append(desc)

        except Exception as e:
            details.append(f"Error reading file: {str(e)}")

        return details, secrets_hints

    def _analyze_readme(self, readme_path: str) -> list:
        hints = []
        try:
            with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            for pattern in self.readme_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    for match in matches:
                        if isinstance(match, tuple):
                            hints.append(f"CI/CD reference: {match[0]}")
                        else:
                            hints.append(f"CI/CD reference: {match}")

        except Exception:
            pass

        return hints

    def _scan_remote_repo(self, repo_url: str, access_token: str = None) -> tuple:
        found_pipelines = []
        secrets_hints = []

        try:
            import requests
        except ImportError:
            self.print_error("requests library required for remote scanning")
            return found_pipelines, secrets_hints

        headers = {}
        if access_token:
            headers["Authorization"] = f"token {access_token}"

        if "github.com" in repo_url:
            found_pipelines, secrets_hints = self._scan_github_repo(repo_url, headers)
        elif "gitlab.com" in repo_url or "gitlab" in repo_url.lower():
            found_pipelines, secrets_hints = self._scan_gitlab_repo(repo_url, headers)
        else:
            found_pipelines, secrets_hints = self._scan_gitea_repo(repo_url, headers)

        return found_pipelines, secrets_hints

    def _scan_github_repo(self, repo_url: str, headers: dict) -> tuple:
        found_pipelines = []
        secrets_hints = []

        try:
            import requests
            
            match = re.search(r'github\.com[/:]([^/]+)/([^/\.]+)', repo_url)
            if not match:
                self.print_error("Could not parse GitHub URL")
                return found_pipelines, secrets_hints

            owner, repo = match.groups()
            api_base = f"https://api.github.com/repos/{owner}/{repo}"

            try:
                resp = requests.get(f"{api_base}/contents/.github/workflows", headers=headers, timeout=10)
                if resp.status_code == 200:
                    workflows = resp.json()
                    for wf in workflows:
                        if wf.get('name', '').endswith(('.yml', '.yaml')):
                            found_pipelines.append({
                                "type": "GitHub Actions workflow",
                                "path": f".github/workflows/{wf['name']}",
                                "details": [f"Download URL: {wf.get('download_url', 'N/A')}"]
                            })
            except Exception:
                pass

            for cicd_name, cicd_info in self.cicd_indicators.items():
                if cicd_name == "github_actions":
                    continue
                for path in cicd_info["paths"]:
                    if "*" in path:
                        continue
                    try:
                        resp = requests.get(f"{api_base}/contents/{path}", headers=headers, timeout=10)
                        if resp.status_code == 200:
                            found_pipelines.append({
                                "type": cicd_info["description"],
                                "path": path,
                                "details": []
                            })
                    except Exception:
                        pass

        except Exception as e:
            self.print_error(f"Error scanning GitHub repo: {str(e)}")

        return found_pipelines, secrets_hints

    def _scan_gitlab_repo(self, repo_url: str, headers: dict) -> tuple:
        found_pipelines = []
        secrets_hints = []

        try:
            import requests
            import urllib.parse

            match = re.search(r'gitlab\.com[/:]([^/]+(?:/[^/]+)*)/([^/\.]+)', repo_url)
            if not match:
                self.print_error("Could not parse GitLab URL")
                return found_pipelines, secrets_hints

            namespace, project = match.groups()
            project_path = urllib.parse.quote(f"{namespace}/{project}", safe='')
            api_base = f"https://gitlab.com/api/v4/projects/{project_path}"

            try:
                resp = requests.get(f"{api_base}/repository/files/.gitlab-ci.yml?ref=main", headers=headers, timeout=10)
                if resp.status_code == 200:
                    found_pipelines.append({
                        "type": "GitLab CI/CD pipeline",
                        "path": ".gitlab-ci.yml",
                        "details": []
                    })
            except Exception:
                pass

        except Exception as e:
            self.print_error(f"Error scanning GitLab repo: {str(e)}")

        return found_pipelines, secrets_hints

    def _scan_gitea_repo(self, repo_url: str, headers: dict) -> tuple:
        found_pipelines = []
        secrets_hints = []

        try:
            import requests

            match = re.search(r'https?://([^/]+)/([^/]+)/([^/\.]+)', repo_url)
            if not match:
                self.print_error("Could not parse Gitea URL")
                return found_pipelines, secrets_hints

            host, owner, repo = match.groups()
            api_base = f"https://{host}/api/v1/repos/{owner}/{repo}"

            paths_to_check = [
                ".github/workflows",
                ".gitlab-ci.yml",
                "Jenkinsfile",
                ".drone.yml",
                ".woodpecker.yml"
            ]

            for path in paths_to_check:
                try:
                    resp = requests.get(f"{api_base}/contents/{path}", headers=headers, timeout=10)
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, list):
                            for item in data:
                                found_pipelines.append({
                                    "type": "GitHub Actions workflow (Gitea)",
                                    "path": f"{path}/{item.get('name', '')}",
                                    "details": []
                                })
                        else:
                            for cicd_name, cicd_info in self.cicd_indicators.items():
                                if path in cicd_info["paths"]:
                                    found_pipelines.append({
                                        "type": cicd_info["description"],
                                        "path": path,
                                        "details": []
                                    })
                                    break
                except Exception:
                    pass

        except Exception as e:
            self.print_error(f"Error scanning Gitea repo: {str(e)}")

        return found_pipelines, secrets_hints

    def _enumerate_git_service(self, rhosts: str, rport: str, access_token: str = None) -> tuple:
        found_pipelines = []
        secrets_hints = []

        try:
            import requests
        except ImportError:
            self.print_error("requests library required")
            return found_pipelines, secrets_hints

        headers = {"User-Agent": "uwu-toolkit/1.0"}
        if access_token:
            headers["Authorization"] = f"token {access_token}"

        base_url = f"http://{rhosts}:{rport}"

        try:
            resp = requests.get(f"{base_url}/api/v1/repos/search?limit=50", headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                repos = data.get('data', [])
                self.print_status(f"Found {len(repos)} repositories on Gitea instance")

                for repo in repos:
                    owner = repo.get('owner', {}).get('login', '')
                    name = repo.get('name', '')
                    if owner and name:
                        repo_url = f"{base_url}/{owner}/{name}"
                        self.print_status(f"Scanning repository: {owner}/{name}")
                        repo_pipelines, repo_secrets = self._scan_gitea_repo(repo_url, headers)
                        for p in repo_pipelines:
                            p['path'] = f"{owner}/{name}/{p['path']}"
                        found_pipelines.extend(repo_pipelines)
                        secrets_hints.extend(repo_secrets)
            else:
                self.print_warning(f"Could not enumerate repos (status: {resp.status_code})")
                self.print_status("Try providing ACCESS_TOKEN for authentication")

        except requests.exceptions.ConnectionError:
            self.print_error(f"Could not connect to {base_url}")
        except Exception as e:
            self.print_error(f"Error enumerating Git service: {str(e)}")

        return found_pipelines, secrets_hints
