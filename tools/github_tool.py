"""
AI AYFAM - GitHub Intelligence Tool
تكامل GitHub الذكي — تحليل المستودعات والأدوات الأمنية الجديدة
"""

import requests
import json
import base64
import re
from datetime import datetime, timedelta


class GitHubTool:
    API = "https://api.github.com"

    def __init__(self, token: str = ""):
        self.token = token
        self.headers = {
            "Authorization": f"token {token}" if token else "",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AI-AYFAM-SecurityAgent/2.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if not token:
            self.headers.pop("Authorization", None)

    def _get(self, path, params=None):
        return requests.get(f"{self.API}{path}", headers=self.headers, params=params, timeout=15)

    def _post(self, path, data):
        return requests.post(f"{self.API}{path}", headers=self.headers, json=data, timeout=15)

    def _put(self, path, data):
        return requests.put(f"{self.API}{path}", headers=self.headers, json=data, timeout=15)

    # ──────────────────────────────────────────────────────────────────────
    #  Connection & Auth
    # ──────────────────────────────────────────────────────────────────────

    def test_connection(self) -> dict:
        if not self.token:
            return {"success": False, "error": "لم يتم إدخال رمز GitHub / No GitHub token set.\n"
                                               "الإعداد / Setup: ayfam --set-github-token YOUR_TOKEN"}
        try:
            r = self._get("/user")
            if r.status_code == 200:
                d = r.json()
                rate = self._get("/rate_limit")
                rate_data = rate.json().get("resources", {}).get("core", {}) if rate.ok else {}
                return {
                    "success": True,
                    "username": d.get("login"), "name": d.get("name"),
                    "email": d.get("email"), "public_repos": d.get("public_repos"),
                    "followers": d.get("followers"),
                    "rate_limit_remaining": rate_data.get("remaining", "?"),
                    "rate_limit_reset": rate_data.get("reset", 0),
                }
            return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:100]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ──────────────────────────────────────────────────────────────────────
    #  Repository Management
    # ──────────────────────────────────────────────────────────────────────

    def get_user_repos(self, sort="updated", per_page=30) -> list:
        try:
            r = self._get("/user/repos", {"per_page": per_page, "sort": sort})
            if r.status_code == 200:
                return [{
                    "name": repo["name"], "full_name": repo["full_name"],
                    "description": repo.get("description") or "",
                    "private": repo["private"], "url": repo["html_url"],
                    "stars": repo["stargazers_count"], "language": repo.get("language") or "",
                    "updated": repo.get("updated_at", "")[:10],
                    "default_branch": repo.get("default_branch", "main"),
                } for repo in r.json()]
        except Exception:
            pass
        return []

    def create_repo(self, name: str, description: str = "", private: bool = True) -> dict:
        try:
            r = self._post("/user/repos", {
                "name": name, "description": description,
                "private": private, "auto_init": True, "gitignore_template": "Python",
            })
            if r.status_code == 201:
                repo = r.json()
                return {"success": True, "full_name": repo["full_name"],
                        "url": repo["html_url"], "clone_url": repo["clone_url"],
                        "default_branch": repo.get("default_branch", "main")}
            return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def upload_file(self, repo_full_name: str, file_path: str, content: str,
                    commit_message: str = "Update by AI AYFAM", branch: str = "main") -> dict:
        try:
            encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")
            sha = None
            existing = self._get(f"/repos/{repo_full_name}/contents/{file_path}")
            if existing.status_code == 200:
                sha = existing.json().get("sha")
            data = {"message": commit_message, "content": encoded, "branch": branch}
            if sha:
                data["sha"] = sha
            r = self._put(f"/repos/{repo_full_name}/contents/{file_path}", data)
            if r.status_code in (200, 201):
                return {"success": True, "url": r.json().get("content", {}).get("html_url", "")}
            return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def push_report(self, repo_full_name: str, report_content: str, report_name: str = None) -> dict:
        if not report_name:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            report_name = f"reports/ayfam-report-{ts}.md"
        return self.upload_file(
            repo_full_name, report_name, report_content,
            f"🛡️ AI AYFAM Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        )

    # ──────────────────────────────────────────────────────────────────────
    #  Security Intelligence from GitHub
    # ──────────────────────────────────────────────────────────────────────

    def get_trending_security_tools(self, days_back: int = 7, max_results: int = 10) -> list:
        """Discover new trending security/hacking tools on GitHub"""
        since = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%d")
        queries = [
            f"topic:security topic:cybersecurity pushed:>{since} stars:>10 language:Python",
            f"topic:pentesting pushed:>{since} stars:>5",
            f"topic:hacking pushed:>{since} stars:>5",
        ]
        all_repos = []
        seen = set()
        for q in queries:
            try:
                r = self._get("/search/repositories", {"q": q, "sort": "stars", "order": "desc", "per_page": 10})
                if r.status_code == 200:
                    for item in r.json().get("items", []):
                        if item["full_name"] not in seen:
                            seen.add(item["full_name"])
                            all_repos.append({
                                "name": item["full_name"],
                                "description": item.get("description") or "",
                                "stars": item["stargazers_count"],
                                "url": item["html_url"],
                                "language": item.get("language") or "",
                                "topics": item.get("topics", []),
                                "updated": item.get("updated_at", "")[:10],
                                "watchers": item.get("watchers_count", 0),
                            })
            except Exception:
                continue

        # Sort by stars and return top results
        all_repos.sort(key=lambda x: x["stars"], reverse=True)
        return all_repos[:max_results]

    def analyze_tool(self, repo_full_name: str) -> dict:
        """Analyze a GitHub repo and explain what it does, how to use it"""
        try:
            # Get repo info
            r = self._get(f"/repos/{repo_full_name}")
            if not r.ok:
                return {"error": f"Repo not found: {repo_full_name}"}
            repo = r.json()

            # Get README
            readme_r = self._get(f"/repos/{repo_full_name}/readme")
            readme = ""
            if readme_r.ok:
                encoded = readme_r.json().get("content", "")
                try:
                    readme = base64.b64decode(encoded).decode("utf-8", errors="replace")[:3000]
                except Exception:
                    pass

            # Get languages
            lang_r = self._get(f"/repos/{repo_full_name}/languages")
            languages = list(lang_r.json().keys()) if lang_r.ok else []

            # Parse README for install/usage
            install_section = ""
            usage_section = ""
            for section in re.split(r"\n#+\s*", readme):
                if re.match(r"(install|setup|getting started)", section, re.I):
                    install_section = section[:500]
                elif re.match(r"(usage|use|how to|example)", section, re.I):
                    usage_section = section[:500]

            # Determine category
            desc = repo.get("description", "").lower()
            topics = repo.get("topics", [])
            category = "Security Tool"
            if any(t in desc + " ".join(topics) for t in ["scanner", "scan"]):
                category = "Network/Port Scanner"
            elif any(t in desc + " ".join(topics) for t in ["fuzzer", "fuzz"]):
                category = "Fuzzer"
            elif any(t in desc + " ".join(topics) for t in ["exploit", "payload"]):
                category = "Exploitation Framework"
            elif any(t in desc + " ".join(topics) for t in ["recon", "osint", "information gathering"]):
                category = "Reconnaissance / OSINT"
            elif any(t in desc + " ".join(topics) for t in ["web", "http", "sql injection", "xss"]):
                category = "Web Security"
            elif any(t in desc + " ".join(topics) for t in ["password", "crack", "hash", "brute"]):
                category = "Password / Hash Tool"
            elif any(t in desc + " ".join(topics) for t in ["forensic", "memory", "volatility"]):
                category = "Forensics"

            return {
                "name": repo_full_name,
                "description": repo.get("description", ""),
                "category": category,
                "stars": repo.get("stargazers_count", 0),
                "language": repo.get("language", ""),
                "all_languages": languages,
                "topics": topics,
                "license": repo.get("license", {}).get("name") if repo.get("license") else "Unknown",
                "last_updated": repo.get("updated_at", "")[:10],
                "readme_preview": readme[:800],
                "install_hint": install_section,
                "usage_hint": usage_section,
                "clone_url": repo.get("clone_url", ""),
                "url": repo.get("html_url", ""),
            }
        except Exception as e:
            return {"error": str(e)}

    def search_cve_exploits(self, cve_id: str) -> list:
        try:
            r = self._get("/search/repositories", {"q": cve_id, "sort": "updated", "per_page": 5})
            if r.ok:
                return [{
                    "name": i["full_name"], "url": i["html_url"],
                    "stars": i["stargazers_count"],
                    "description": i.get("description") or "",
                    "updated": i.get("updated_at", "")[:10],
                } for i in r.json().get("items", [])]
        except Exception:
            pass
        return []

    def get_security_advisories(self, ecosystem: str = None, max_results: int = 10) -> list:
        try:
            params = {"per_page": max_results, "type": "reviewed"}
            if ecosystem:
                params["ecosystem"] = ecosystem
            r = self._get("/advisories", params)
            if r.ok:
                advisories = r.json()
                return [{
                    "id": a.get("ghsa_id"), "summary": a.get("summary"),
                    "severity": a.get("severity"), "published": a.get("published_at", "")[:10],
                    "cve_id": a.get("cve_id"), "url": a.get("html_url"),
                    "packages": [v.get("package", {}).get("name") for v in a.get("vulnerabilities", [])],
                } for a in advisories]
        except Exception as e:
            return [{"error": str(e)}]
        return []

    def suggest_install(self, repo_info: dict) -> str:
        """Generate install command for a tool"""
        lang = repo_info.get("language", "").lower()
        clone_url = repo_info.get("clone_url", "")
        name = repo_info.get("name", "").split("/")[-1]
        hint = repo_info.get("install_hint", "").lower()

        if "pip install" in hint:
            m = re.search(r"pip install (\S+)", hint)
            return f"pip install {m.group(1)}" if m else f"git clone {clone_url} && cd {name} && pip install -r requirements.txt"
        if lang == "python":
            return f"git clone {clone_url}\ncd {name}\npip install -r requirements.txt 2>/dev/null || pip install ."
        if lang == "go":
            return f"go install {clone_url.replace('https://github.com/', 'github.com/')}@latest"
        if lang in ("c", "c++"):
            return f"git clone {clone_url}\ncd {name}\nmake && sudo make install"
        if lang == "ruby":
            return f"git clone {clone_url}\ncd {name}\ngem install bundler && bundle install"
        return f"git clone {clone_url}\ncd {name}"
