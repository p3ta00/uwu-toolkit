"""
Web Username Harvester Module
Scrapes names from web pages and generates username permutations
for password spraying, brute-forcing, or Kerberos attacks.
"""

import os
import re
import tempfile
from urllib.parse import urljoin, urlparse
from core.module_base import ModuleBase, ModuleType, Platform


class UsernameHarvest(ModuleBase):
    """
    Scrape employee names from web pages (e.g. "About Us", "Meet Our Team")
    and generate username permutations using username-anarchy or a built-in
    Python fallback.
    """

    def __init__(self):
        super().__init__()
        self.name = "web/username_harvest"
        self.description = "Scrape names from web pages and generate username permutations"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WEB
        self.tags = ["web", "recon", "username", "osint", "harvest"]

        self.register_option("TARGET_URL", "URL to scrape for names (required unless NAME_FILE is set)", required=False)
        self.register_option("DEPTH", "Crawl depth (0 = full site, 1 = single page, 2+ = follow N levels deep)", default=0)
        self.register_option("OUTPUT", "Output file for generated usernames", default="usernames.txt")
        self.register_option("DOMAIN_SUFFIX", "Append @domain to usernames (e.g. @corp.local)", default="")
        self.register_option("SELECTOR", "CSS selector to narrow scraping scope", default="")
        self.register_option("NAME_FILE", "Skip scraping; use names from a file instead (one 'First Last' per line)", default="")
        self.register_option("INCLUDE_TESTIMONIALS", "Also extract names from testimonial attributions (lines starting with '- ')", default="true")
        self.register_option("FORMATS", "Comma-separated username-anarchy format plugins to use, or 'all'", default="all")

    def check(self) -> bool:
        """Verify that requests and lxml are importable"""
        try:
            import requests  # noqa: F401
            from lxml import html  # noqa: F401
            return True
        except ImportError as e:
            self.print_error(f"Missing dependency: {e}")
            return False

    def run(self) -> bool:
        name_file = self.get_option("NAME_FILE")

        if name_file:
            names = self._load_names_from_file(name_file)
        else:
            target_url = self.get_option("TARGET_URL")
            if not target_url:
                self.print_error("TARGET_URL is required when NAME_FILE is not set")
                return False
            # Auto-prepend http:// if no scheme given
            if not target_url.startswith(("http://", "https://")):
                target_url = f"http://{target_url}"
                self.set_option("TARGET_URL", target_url)
                self.print_status(f"Auto-corrected URL to {target_url}")
            if not self.check():
                return False
            names = self._scrape_names()

        if not names:
            self.print_error("No names found")
            return False

        self.print_good(f"Discovered {len(names)} unique name(s):")
        for name in sorted(names):
            self.print_line(f"    {name}")
        self.print_line()

        usernames = self._generate_usernames(names)

        if not usernames:
            self.print_error("No usernames generated")
            return False

        domain_suffix = self.get_option("DOMAIN_SUFFIX")
        if domain_suffix:
            if not domain_suffix.startswith("@"):
                domain_suffix = f"@{domain_suffix}"
            domain_variants = [f"{u}{domain_suffix}" for u in usernames]
            usernames = usernames + domain_variants

        output_file = self.get_option("OUTPUT")
        try:
            with open(output_file, "w") as f:
                f.write("\n".join(sorted(set(usernames))) + "\n")
            self.print_good(f"Wrote {len(set(usernames))} usernames to {output_file}")
        except IOError as e:
            self.print_error(f"Could not write output file: {e}")
            return False

        self.print_line()
        self.print_status("Sample usernames:")
        for u in sorted(set(usernames))[:20]:
            self.print_line(f"    {u}")
        if len(set(usernames)) > 20:
            self.print_line(f"    ... and {len(set(usernames)) - 20} more")

        return True

    # =========================================================================
    # Name Extraction
    # =========================================================================

    def _scrape_names(self) -> list:
        """Scrape names from TARGET_URL and follow same-domain links based on DEPTH"""
        import requests
        from lxml import html

        target_url = self.get_option("TARGET_URL")
        depth = int(self.get_option("DEPTH"))
        selector = self.get_option("SELECTOR")
        max_pages = 100  # safety cap to avoid runaway crawls

        parsed_base = urlparse(target_url)
        base_domain = parsed_base.netloc

        visited = set()
        to_visit = [(target_url, 1)]
        all_names = set()

        while to_visit:
            if len(visited) >= max_pages:
                self.print_warning(f"Reached max page limit ({max_pages}), stopping crawl")
                break

            url, current_depth = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            self.print_status(f"Fetching {url}")
            try:
                resp = requests.get(url, timeout=15, verify=False)
                resp.raise_for_status()
            except Exception as e:
                self.print_warning(f"Failed to fetch {url}: {e}")
                continue

            tree = html.fromstring(resp.text)

            # Extract names from this page
            names = self._extract_names_from_tree(tree, selector)
            all_names.update(names)

            # Crawl deeper: depth=0 means unlimited, otherwise respect limit
            if depth == 0 or current_depth < depth:
                for link_el in tree.xpath("//a[@href]"):
                    href = link_el.get("href", "")
                    abs_url = urljoin(url, href)
                    link_parsed = urlparse(abs_url)
                    # Strip fragments and query strings for dedup
                    abs_url = abs_url.split("#")[0]
                    # Only follow same-domain HTML links (skip files)
                    if link_parsed.netloc != base_domain:
                        continue
                    if abs_url in visited:
                        continue
                    # Skip non-page resources
                    path_lower = link_parsed.path.lower()
                    if any(path_lower.endswith(ext) for ext in (
                        ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg",
                        ".css", ".js", ".zip", ".tar", ".gz", ".exe",
                    )):
                        continue
                    to_visit.append((abs_url, current_depth + 1))

        self.print_status(f"Crawled {len(visited)} page(s)")

        return sorted(all_names)

    def _extract_names_from_tree(self, tree, selector: str) -> set:
        """Extract names from an lxml tree using multiple strategies"""
        from lxml import html as lxml_html

        names = set()

        # Determine the scope elements
        if selector:
            scope_elements = tree.cssselect(selector)
        else:
            scope_elements = [tree]

        for scope in scope_elements:
            # Strategy 1: headings inside card/team sections
            for tag in ["h2", "h3", "h4"]:
                for el in scope.xpath(f".//{tag}"):
                    text = (el.text_content() or "").strip()
                    if self._looks_like_name(text):
                        names.add(text)

            # Strategy 2: <em> / <i> tags (testimonial attributions)
            include_testimonials = str(self.get_option("INCLUDE_TESTIMONIALS")).lower() == "true"
            if include_testimonials:
                for el in scope.xpath(".//em | .//i"):
                    text = (el.text_content() or "").strip()
                    # Strip leading "- " common in testimonials
                    text = re.sub(r"^[-–—]\s*", "", text)
                    if self._looks_like_name(text):
                        names.add(text)

            # Strategy 3: regex over all text content for "Firstname Lastname"
            full_text = scope.text_content() or ""
            for match in re.finditer(r"\b([A-Z][a-z]{1,20})\s+([A-Z][a-z]{1,20})\b", full_text):
                candidate = match.group(0)
                if self._looks_like_name(candidate):
                    names.add(candidate)

        return names

    # Common English words (title-cased on web pages) that are NOT person names.
    # Used to filter false positives from the regex name extraction strategy.
    _NON_NAME_WORDS = {
        # Web navigation / UI
        "About", "Home", "Services", "Contact", "Portfolio", "Blog", "News",
        "Login", "Signup", "Register", "Search", "Menu", "Navigation", "Footer",
        "Header", "Sidebar", "Content", "Main", "Page", "Site", "View", "Read",
        "More", "Click", "Here", "Back", "Next", "Previous", "Submit", "Close",
        "Open", "Download", "Upload", "Share", "Print", "Save", "Edit", "Delete",
        # Common website section words
        "Meet", "Our", "Team", "Staff", "Members", "People", "Leadership",
        "Welcome", "History", "Mission", "Vision", "Values", "Story", "Culture",
        "Clients", "Customers", "Partners", "Testimonials", "Reviews", "Feedback",
        "What", "Why", "How", "Where", "When", "Who", "Get", "Started", "Find",
        "Out", "Learn", "Discover", "Explore", "Join", "Start", "Free", "New",
        # Job titles / roles
        "Senior", "Junior", "Lead", "Chief", "Director", "Manager", "Officer",
        "President", "Vice", "Head", "Executive", "Founder", "Owner", "Partner",
        "Analyst", "Engineer", "Developer", "Designer", "Architect", "Consultant",
        "Coordinator", "Administrator", "Specialist", "Associate", "Assistant",
        "Intern", "Supervisor", "Advisor", "Strategist", "Technician",
        # Departments / domains
        "Finance", "Marketing", "Sales", "Human", "Resources", "Technology",
        "Security", "Operations", "Legal", "Compliance", "Accounting", "Support",
        "Research", "Development", "Product", "Quality", "Data", "Digital",
        "Creative", "Communications", "Public", "Relations", "Customer",
        "Information", "Business", "Corporate", "Global", "Regional",
        # Common adjectives/nouns on web pages
        "Professional", "Trusted", "Reliable", "Expert", "Industry", "Leading",
        "Best", "Top", "Great", "Good", "Better", "Premium", "Quality", "Custom",
        "Full", "Complete", "Total", "All", "Rights", "Reserved", "Copyright",
        "Privacy", "Policy", "Terms", "Conditions", "Group", "Company", "Solutions",
        "Web", "Online", "Cloud", "Mobile", "Smart", "Modern", "Simple", "Easy",
        "Fast", "Secure", "Safe", "Trust", "Say", "See", "Try", "Use", "Make",
        "Take", "Give", "Know", "Think", "Want", "Need", "Help", "Show", "Work",
        "Call", "Come", "Keep", "Let", "Run", "Set", "Turn", "Move", "Live",
        "Long", "High", "Low", "Big", "Small", "Old", "Young", "Real", "True",
        "Sure", "Right", "Left", "Most", "Every", "Each", "Such", "Just", "Only",
        "Very", "Still", "Also", "Well", "Even", "Much", "Both", "Some", "Any",
        "Few", "Many", "Own", "Other", "Part", "Role", "Type", "Case", "End",
        # Financial / banking / business terms
        "Loan", "Banking", "Accounts", "Personal", "Online", "Investment",
        "Savings", "Credit", "Debit", "Payment", "Transfer", "Balance",
        "Growth", "Mistakes", "Texas", "Institution", "Texan", "Garage",
        # Location / time / general
        "Today", "Beyond", "Star", "Lone", "Found", "Not", "Name",
        "Warning", "Contrary", "Despite", "True", "Feature", "Broken",
    }

    def _looks_like_name(self, text: str) -> bool:
        """Heuristic check if text looks like a person's name (First Last)"""
        if not text:
            return False
        # Must be exactly 2 or 3 words, each capitalized, no digits/punctuation
        parts = text.split()
        if len(parts) < 2 or len(parts) > 3:
            return False
        for part in parts:
            if not re.match(r"^[A-Z][a-z]{1,20}$", part):
                return False
        # Reject if ANY word is a common non-name word
        for part in parts:
            if part in self._NON_NAME_WORDS:
                return False
        return True

    def _load_names_from_file(self, filepath: str) -> list:
        """Load names from a file (one 'First Last' per line)"""
        names = []
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        names.append(line)
        except IOError as e:
            self.print_error(f"Could not read name file: {e}")
        return names

    # =========================================================================
    # Username Generation
    # =========================================================================

    def _generate_usernames(self, names: list) -> list:
        """Generate username permutations from a list of names"""
        anarchy_path = "/opt/tools/username-anarchy/username-anarchy"
        formats = self.get_option("FORMATS")

        if os.path.isfile(anarchy_path) and os.access(anarchy_path, os.X_OK):
            return self._generate_with_anarchy(names, anarchy_path, formats)
        else:
            self.print_warning("username-anarchy not found, using built-in generator")
            return self._generate_builtin(names)

    def _generate_with_anarchy(self, names: list, anarchy_path: str, formats: str) -> list:
        """Use username-anarchy to generate usernames"""
        try:
            tmp_input = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="uwu_names_"
            )
            for name in names:
                tmp_input.write(name + "\n")
            tmp_input.close()

            cmd = [anarchy_path, "--input-file", tmp_input.name]
            if formats and formats.lower() != "all":
                cmd.extend(["--select-format", formats])

            self.print_status(f"Running username-anarchy on {len(names)} name(s)...")
            rc, stdout, stderr = self.run_command(cmd, timeout=60)

            if rc != 0:
                self.print_warning(f"username-anarchy failed (rc={rc}): {stderr.strip()}")
                self.print_status("Falling back to built-in generator")
                return self._generate_builtin(names)

            usernames = [line.strip() for line in stdout.splitlines() if line.strip()]
            self.print_good(f"username-anarchy generated {len(usernames)} usernames")
            return usernames

        except Exception as e:
            self.print_warning(f"username-anarchy error: {e}")
            self.print_status("Falling back to built-in generator")
            return self._generate_builtin(names)

        finally:
            try:
                os.unlink(tmp_input.name)
            except OSError:
                pass

    def _generate_builtin(self, names: list) -> list:
        """Built-in Python username generator (fallback)"""
        usernames = set()

        for full_name in names:
            parts = full_name.strip().split()
            if len(parts) < 2:
                continue
            first = parts[0].lower()
            last = parts[-1].lower()
            fi = first[0]  # first initial
            li = last[0]   # last initial

            variants = [
                first,                  # alex
                f"{fi}{last}",          # ameier
                f"{fi}.{last}",         # a.meier
                f"{first}.{last}",      # alex.meier
                f"{first}{last}",       # alexmeier
                f"{first}{li}",         # alexm
                last,                   # meier
                f"{last}.{fi}",         # meier.a
                f"{last}.{first}",      # meier.alex
                f"{li}{first}",         # malex
                f"{li}.{first}",        # m.alex
                f"{fi}{li}",            # am
                f"{first}.{li}",        # alex.m
            ]

            usernames.update(variants)

        self.print_good(f"Built-in generator produced {len(usernames)} usernames")
        return sorted(usernames)
