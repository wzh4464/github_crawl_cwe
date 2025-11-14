from __future__ import annotations

import csv
import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

import httpx
from dotenv import dotenv_values
from openai import OpenAI


LANGUAGE_SUFFIXES: Dict[str, Tuple[str, ...]] = {
    "java": (".java",),
    "c/c++": (
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hpp",
        ".hh",
        ".hxx",
        ".ipp",
    ),
    "python": (".py",),
}

GITHUB_API = "https://api.github.com"
MAX_RECORDS_PER_CWE = 10000
SEARCH_PER_PAGE = 100
REQUEST_TIMEOUT = 30.0
BENIGN_PREFIX = "+"
VULNERABLE_PREFIX = "-"
MIN_STARS_EXCLUSIVE = 100
MAX_FILES_PER_PR = 3
AI_CONFIDENCE_THRESHOLD = 0.7
MAX_AI_KEYWORDS_PER_CWE = 5


@dataclass
class RecordWrapper:
    language: str
    cwe: str
    merged_at: str
    entry: Dict


class CWEDescriptionManager:
    """Manages CWE descriptions from target.csv"""

    def __init__(self, target_csv: Path):
        self.descriptions: Dict[str, str] = {}
        self._load_descriptions(target_csv)

    def _load_descriptions(self, target_csv: Path) -> None:
        """Load CWE descriptions from target.csv"""
        if not target_csv.exists():
            return
        with target_csv.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if "CWE" not in reader.fieldnames or "description" not in reader.fieldnames:
                return
            for row in reader:
                cwe = (row.get("CWE") or "").strip()
                description = (row.get("description") or "").strip()
                if cwe and description:
                    self.descriptions[cwe] = description

    def get_description(self, cwe: str) -> str:
        """Get description for a CWE, returns empty string if not found"""
        return self.descriptions.get(cwe, "")


class AIClient:
    """Client for AI model interactions using OpenAI API"""

    def __init__(self, env: Dict[str, str]):
        self.client = OpenAI(
            base_url=env.get("API_BASE_URL", "https://api.openai.com/v1"),
            api_key=env.get("API_KEY", "")
        )
        self.model_name = env.get("MODEL_NAME", "gpt-4o")
        self.meta_model_name = env.get("META_MODEL_NAME", "gpt-4o")

    def generate_keywords(self, cwe: str, description: str) -> List[str]:
        """Generate search keywords from CWE description using AI"""
        if not description:
            return []

        prompt = f"""Given this CWE vulnerability description:

CWE: {cwe}
Description: {description}

Generate 3-5 GitHub search queries to find pull requests that fix this vulnerability.
Focus on:
1. Technical terms and code patterns
2. Security-related terminology
3. Common fix patterns
4. Programming concepts (Java, C/C++, Python)

Return ONLY a JSON array of search query strings, nothing else.
Example: ["input validation vulnerability", "sanitize user input", "XSS prevention"]"""

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a security expert helping to find vulnerability fixes. Return only valid JSON arrays."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=500
            )

            content = response.choices[0].message.content.strip()
            # Remove markdown code blocks if present
            if content.startswith("```"):
                content = content.split("\n", 1)[1]
                content = content.rsplit("```", 1)[0]

            keywords = json.loads(content)
            if isinstance(keywords, list):
                return keywords[:MAX_AI_KEYWORDS_PER_CWE]
            return []
        except Exception as e:
            print(f"Error generating keywords for {cwe}: {e}")
            return []

    def validate_relevance(self, cwe: str, cwe_description: str, pr_data: Dict, patch_summary: str = "") -> Dict:
        """Validate if PR is relevant to the CWE using AI"""
        pr_title = pr_data.get("title") or ""
        pr_body = (pr_data.get("body") or "")[:2000]  # Limit body length, handle None

        # If patch_summary is too long, truncate it
        if len(patch_summary) > 1000:
            patch_summary = patch_summary[:1000] + "... (truncated)"

        prompt = f"""Analyze if this GitHub pull request addresses the specified vulnerability:

CWE: {cwe}
CWE Description: {cwe_description}

PR Title: {pr_title}
PR Body: {pr_body[:500]}
Code Changes Summary: {patch_summary}

Tasks:
1. Is this PR fixing the specified CWE vulnerability? Answer yes/no/uncertain
2. Confidence level (0.0 to 1.0)
3. Brief reasoning (1-2 sentences)

Return ONLY a JSON object with keys: is_relevant (boolean), confidence (float), reasoning (string).
Example: {{"is_relevant": true, "confidence": 0.85, "reasoning": "The PR fixes path traversal by validating file paths."}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.meta_model_name,
                messages=[
                    {"role": "system", "content": "You are a security expert analyzing vulnerability fixes. Be conservative: only mark as relevant with high confidence if there's clear evidence. Return only valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=300
            )

            content = response.choices[0].message.content.strip()
            # Remove markdown code blocks if present
            if content.startswith("```"):
                content = content.split("\n", 1)[1]
                content = content.rsplit("```", 1)[0]

            result = json.loads(content)
            return {
                "is_relevant": result.get("is_relevant", False),
                "confidence": float(result.get("confidence", 0.0)),
                "reasoning": result.get("reasoning", "")
            }
        except Exception as e:
            print(f"Error validating relevance for {cwe}: {e}")
            return {"is_relevant": False, "confidence": 0.0, "reasoning": f"Error: {str(e)}"}

    def identify_primary_file(self, files: List[Dict], cwe_description: str) -> Optional[Dict]:
        """Identify the primary vulnerable file in a multi-file PR"""
        if not files or len(files) == 1:
            return files[0] if files else None

        # Filter files by language first
        valid_files = []
        for f in files:
            filename = f.get("filename", "")
            if self._is_valid_language(filename):
                valid_files.append(f)

        if not valid_files:
            return None
        if len(valid_files) == 1:
            return valid_files[0]

        # Use AI to identify primary file
        file_descriptions = []
        for i, f in enumerate(valid_files[:5]):  # Limit to 5 files
            filename = f.get("filename") or ""
            patch = (f.get("patch") or "")[:500]  # First 500 chars, handle None
            file_descriptions.append(f"{i}. {filename}\n   Changes: {patch[:200]}")

        files_text = "\n".join(file_descriptions)

        prompt = f"""Given this vulnerability description:
{cwe_description}

And these files changed in a PR:
{files_text}

Which file number (0-{len(valid_files)-1}) contains the PRIMARY vulnerability fix (not tests, docs, or configs)?
Return ONLY the number, nothing else."""

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are identifying the main vulnerability fix file. Return only a single number."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=10
            )

            content = response.choices[0].message.content.strip()
            file_index = int(content)
            if 0 <= file_index < len(valid_files):
                return valid_files[file_index]
        except Exception as e:
            print(f"Error identifying primary file: {e}")

        # Fallback: return first valid file
        return valid_files[0] if valid_files else None

    @staticmethod
    def _is_valid_language(filename: str) -> bool:
        """Check if file has a valid language extension"""
        suffix = Path(filename).suffix.lower()
        for suffixes in LANGUAGE_SUFFIXES.values():
            if suffix in suffixes:
                return True
        return False


class GithubCweCrawler:
    def __init__(self) -> None:
        self.root = Path(__file__).resolve().parent
        self.target_csv = self.root / "target.csv"
        self.response_dir = self.root / "response"
        self.records_dir = self.response_dir / "records"
        self.progress_log = self.response_dir / "progress.log"
        self.output_file = self.root / "github_cwe_results.json"
        self.target_counts_copy = self.root / "target_with_counts.csv"
        self.response_dir.mkdir(parents=True, exist_ok=True)
        self.records_dir.mkdir(parents=True, exist_ok=True)
        env = dotenv_values(self.root / ".env")
        token = env.get("GITHUB_API_KEY")
        if not token:
            raise RuntimeError("GITHUB_API_KEY missing in .env")
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "github-crawl-cwe-script",
        }
        self.client = httpx.Client(
            base_url=GITHUB_API, headers=headers, timeout=REQUEST_TIMEOUT
        )
        self.repo_cache: Dict[str, Dict] = {}
        self.counts: Dict[str, int] = {}
        # Initialize AI components
        self.cwe_manager = CWEDescriptionManager(self.target_csv)
        self.ai_client = AIClient(env)
        self.keyword_cache: Dict[str, List[str]] = {}

    def run(self) -> None:
        try:
            for cwe in self.iter_cwes():
                self.log_progress(f"Starting crawl for {cwe}")
                count = self.process_cwe(cwe)
                self.counts[cwe] = count
                self.log_progress(f"Finished {cwe} with {count} record(s)")
        finally:
            self.client.close()
        self.log_progress("Building consolidated output")
        self.build_final_output()
        self.log_progress("Writing target copy with counts")
        self.write_target_counts()
        self.log_progress("Crawl completed")

    def iter_cwes(self) -> Iterator[str]:
        if not self.target_csv.exists():
            raise FileNotFoundError(self.target_csv)
        with self.target_csv.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if "CWE" not in reader.fieldnames:
                raise ValueError("target.csv must contain 'CWE' column")
            for row in reader:
                cwe = (row.get("CWE") or "").strip()
                if not cwe:
                    continue
                yield cwe

    def process_cwe(self, cwe: str) -> int:
        records_path = self.records_dir / f"{cwe}.jsonl"
        total_written = 0
        with records_path.open("w", encoding="utf-8") as rec_file:
            for item in self.search_prs(cwe):
                if total_written >= MAX_RECORDS_PER_CWE:
                    break
                record = self.process_search_item(cwe, item)
                if not record:
                    continue
                rec_file.write(json.dumps(record.__dict__) + "\n")
                total_written += 1
                if total_written % 10 == 0:
                    self.log_progress(f"{cwe}: {total_written} record(s) written")
        return total_written

    def get_ai_keywords(self, cwe: str) -> List[str]:
        """Get or generate AI keywords for a CWE (with caching)"""
        if cwe in self.keyword_cache:
            return self.keyword_cache[cwe]

        description = self.cwe_manager.get_description(cwe)
        if not description:
            self.log_progress(f"{cwe}: No description found, using CWE mention only")
            return []

        self.log_progress(f"{cwe}: Generating AI keywords...")
        keywords = self.ai_client.generate_keywords(cwe, description)
        self.keyword_cache[cwe] = keywords
        self.log_progress(f"{cwe}: Generated {len(keywords)} keyword(s): {keywords}")
        return keywords

    def search_prs(self, cwe: str) -> Iterator[Dict]:
        seen_urls: set = set()  # Track seen PRs to avoid duplicates

        # Search 1: Original CWE mention search
        query = f'"{cwe}" is:pr is:merged'
        self.log_progress(f"{cwe}: Searching with CWE mention...")
        for item in self._execute_search(cwe, query, "cwe_search"):
            pr_url = item.get("html_url")
            if pr_url not in seen_urls:
                seen_urls.add(pr_url)
                yield item

        # Search 2: AI-generated keyword searches
        keywords = self.get_ai_keywords(cwe)
        for idx, keyword in enumerate(keywords):
            keyword_query = f'{keyword} is:pr is:merged'
            self.log_progress(f"{cwe}: Searching with keyword: {keyword}")
            for item in self._execute_search(cwe, keyword_query, f"keyword_{idx}"):
                pr_url = item.get("html_url")
                if pr_url not in seen_urls:
                    seen_urls.add(pr_url)
                    yield item

    def _execute_search(self, cwe: str, query: str, label_prefix: str) -> Iterator[Dict]:
        """Execute a single GitHub search query"""
        page = 1
        while page <= 3:  # Limit pages per keyword search to avoid too many API calls
            params = {
                "q": query,
                "sort": "updated",
                "order": "desc",
                "per_page": SEARCH_PER_PAGE,
                "page": page,
            }
            data, headers = self.request_json(
                "GET", "/search/issues", params=params, cwe=cwe, label=f"{label_prefix}_page_{page}"
            )
            items = data.get("items", [])
            if not items:
                break
            for item in items:
                yield item
            if "next" not in self.parse_link_header(headers.get("link", "")):
                break
            page += 1

    def process_search_item(self, cwe: str, item: Dict) -> Optional[RecordWrapper]:
        pull_info = item.get("pull_request") or {}
        pull_url = pull_info.get("url")
        if not pull_url:
            return None
        repo_full_name = self.extract_repo_full_name(item.get("repository_url"))
        if not repo_full_name:
            return None
        if not self.repo_meets_star_requirement(
            cwe, repo_full_name, cache_key=f"{repo_full_name}_repo"
        ):
            return None
        pr_data = self.fetch_pull_request(cwe, pull_url, repo_full_name, item.get("number"))
        if not pr_data:
            return None
        if not pr_data.get("merged_at"):
            return None

        # Fetch files first to prepare patch summary for AI validation
        pr_number = pr_data.get("number")
        files = self.fetch_pull_files(cwe, repo_full_name, pr_number)
        if not files or len(files) > MAX_FILES_PER_PR:
            return None

        # Use AI to validate relevance
        cwe_description = self.cwe_manager.get_description(cwe)
        patch_summary = "\n".join([f"{f.get('filename')}: {(f.get('patch') or '')[:200]}" for f in files[:3]])
        validation = self.ai_client.validate_relevance(cwe, cwe_description, pr_data, patch_summary)

        if not validation.get("is_relevant", False):
            self.log_progress(f"{cwe}: PR#{pr_number} not relevant - {validation.get('reasoning', 'N/A')}")
            return None

        confidence = validation.get("confidence", 0.0)
        if confidence < AI_CONFIDENCE_THRESHOLD:
            self.log_progress(f"{cwe}: PR#{pr_number} low confidence {confidence:.2f} - {validation.get('reasoning', 'N/A')}")
            return None

        self.log_progress(f"{cwe}: PR#{pr_number} ACCEPTED (confidence: {confidence:.2f}) - {validation.get('reasoning', 'N/A')}")

        # If multiple files, use AI to identify primary vulnerable file
        if len(files) == 1:
            file_entry = files[0]
        else:
            file_entry = self.ai_client.identify_primary_file(files, cwe_description)
            if not file_entry:
                self.log_progress(f"{cwe}: PR#{pr_number} - could not identify primary file")
                return None
            self.log_progress(f"{cwe}: PR#{pr_number} - selected primary file: {file_entry.get('filename')}")
        patch = file_entry.get("patch")
        if not patch:
            return None
        language = self.detect_language(file_entry.get("filename", ""))
        if not language:
            return None
        commit_sha = pr_data.get("merge_commit_sha")
        if not commit_sha:
            return None
        commit_url = f"https://github.com/{repo_full_name}/commit/{commit_sha}"
        issue_url = pr_data.get("html_url")
        merged_at = pr_data.get("merged_at")
        record = RecordWrapper(
            language=language,
            cwe=cwe,
            merged_at=merged_at,
            entry={
                "benign_code": {
                    "context": file_entry.get("filename"),
                    "class": None,
                    "func": None,
                    "lines": self.extract_patch_context(patch, BENIGN_PREFIX),
                },
                "vulnerable_code": {
                    "context": file_entry.get("filename"),
                    "class": None,
                    "func": None,
                    "lines": self.extract_patch_context(patch, VULNERABLE_PREFIX),
                },
                "source": "github",
                "commit_url": commit_url,
                "CWE": cwe,
                "other_CWEs": self.find_other_patterns(
                    pr_data, pattern=r"CWE-\\d+", primary=cwe
                ),
                "other_CWDs": self.find_other_patterns(pr_data, pattern=r"CWD-\\d+"),
                "issue_url": issue_url,
            },
        )
        return record

    def fetch_pull_request(
        self, cwe: str, pull_url: str, repo_full_name: str, issue_number: Optional[int]
    ) -> Optional[Dict]:
        label = f"{repo_full_name.replace('/', '__')}_pr_{issue_number or 'unknown'}"
        data, _ = self.request_json("GET", pull_url, cwe=cwe, label=label)
        return data

    def fetch_pull_files(self, cwe: str, repo_full_name: str, pr_number: Optional[int]) -> List[Dict]:
        if not pr_number:
            return []
        endpoint = f"/repos/{repo_full_name}/pulls/{pr_number}/files"
        params = {"per_page": 100, "page": 1}
        label = f"{repo_full_name.replace('/', '__')}_pr_{pr_number}_files"
        data, headers = self.request_json("GET", endpoint, params=params, cwe=cwe, label=label)
        if "next" in self.parse_link_header(headers.get("link", "")):
            return []
        return data

    def repo_meets_star_requirement(self, cwe: str, repo_full_name: str, cache_key: str) -> bool:
        cached = self.repo_cache.get(repo_full_name)
        if cached is not None:
            return cached.get("stargazers_count", 0) > MIN_STARS_EXCLUSIVE
        endpoint = f"/repos/{repo_full_name}"
        data, _ = self.request_json("GET", endpoint, cwe=cwe, label=cache_key)
        self.repo_cache[repo_full_name] = data
        return data.get("stargazers_count", 0) > MIN_STARS_EXCLUSIVE

    @staticmethod
    def parse_link_header(header_value: str) -> Dict[str, str]:
        links: Dict[str, str] = {}
        if not header_value:
            return links
        parts = header_value.split(",")
        for part in parts:
            section = part.strip().split(";")
            if len(section) < 2:
                continue
            url_part = section[0].strip()
            if not url_part.startswith("<") or not url_part.endswith(">"):
                continue
            url = url_part[1:-1]
            rel = None
            for attribute in section[1:]:
                attribute = attribute.strip()
                if attribute.startswith('rel='):
                    rel_value = attribute.split("=", 1)[1].strip('"')
                    rel = rel_value
                    break
            if rel:
                links[rel] = url
        return links

    def request_json(
        self,
        method: str,
        endpoint: str,
        *,
        params: Optional[Dict] = None,
        cwe: str,
        label: str,
    ) -> Tuple[Dict, Dict[str, str]]:
        url = endpoint
        if not endpoint.startswith("http"):
            url = f"{GITHUB_API}{endpoint}"
        while True:
            response = self.client.request(method, url, params=params)
            remaining = response.headers.get("X-RateLimit-Remaining")
            if response.status_code == 403 and remaining == "0":
                reset_ts = response.headers.get("X-RateLimit-Reset")
                sleep_for = max(int(reset_ts or 0) - int(time.time()) + 1, 1)
                self.log_progress(f"Rate limited, sleeping {sleep_for}s")
                time.sleep(sleep_for)
                continue
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError:
                self.save_response_payload(cwe, label + "_error", response.text)
                raise
            data = response.json()
            self.save_response_payload(cwe, label, data)
            return data, response.headers

    def save_response_payload(self, cwe: str, label: str, data) -> None:
        safe_label = label.replace("/", "__")
        target_dir = self.response_dir / cwe
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / f"{safe_label}.json"
        if isinstance(data, str):
            path.write_text(data, encoding="utf-8")
        else:
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def extract_repo_full_name(self, repository_url: Optional[str]) -> Optional[str]:
        if not repository_url:
            return None
        parts = repository_url.split("/repos/")
        if len(parts) != 2:
            return None
        return parts[1]

    def detect_language(self, filename: str) -> Optional[str]:
        suffix = Path(filename).suffix.lower()
        for language, suffixes in LANGUAGE_SUFFIXES.items():
            if suffix in suffixes:
                return language
        return None

    def extract_patch_context(self, patch: str, target_prefix: str) -> List[str]:
        lines = patch.splitlines()
        collected: List[str] = []
        seen = set()
        for idx, raw_line in enumerate(lines):
            if not raw_line or raw_line.startswith(("@@", "+++", "---")):
                continue
            if not raw_line.startswith(target_prefix):
                continue
            for offset in (-1, 0, 1):
                pos = idx + offset
                if pos < 0 or pos >= len(lines):
                    continue
                candidate = lines[pos]
                if not candidate or candidate.startswith(("@@", "+++", "---")):
                    continue
                content = self.clean_diff_line(candidate)
                key = (pos, content)
                if key in seen:
                    continue
                seen.add(key)
                collected.append(content)
        return collected

    @staticmethod
    def clean_diff_line(line: str) -> str:
        if not line:
            return ""
        prefix = line[0]
        if prefix in "+- ":
            return line[1:]
        return line

    def find_other_patterns(self, pr_data: Dict, pattern: str, primary: Optional[str] = None) -> List[str]:
        regex = re.compile(pattern, re.IGNORECASE)
        text = " ".join(
            filter(
                None,
                [
                    pr_data.get("title", ""),
                    pr_data.get("body", ""),
                ],
            )
        )
        matches = sorted({m.group(0).upper() for m in regex.finditer(text)})
        if primary:
            primary_upper = primary.upper()
            matches = [m for m in matches if m != primary_upper]
        return matches

    def build_final_output(self) -> None:
        cwe_to_cwd = self.load_cwe_to_cwd_map()
        aggregator: Dict[str, Dict[str, List[Tuple[str, Dict]]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for record_file in sorted(self.records_dir.glob("CWE-*.jsonl")):
            with record_file.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    language = data["language"]
                    cwe = data["cwe"]
                    merged_at = data["merged_at"]
                    entry = data["entry"]
                    cwd = cwe_to_cwd.get(cwe)
                    if not cwd:
                        self.log_progress(f"{cwe}: Missing CWD mapping, skipping record")
                        continue
                    aggregator[language][cwd].append((merged_at, entry))
        result = {}
        for language, cwd_map in aggregator.items():
            result_language = {}
            for cwd, entries in cwd_map.items():
                sorted_entries = sorted(
                    entries,
                    key=lambda item: datetime.fromisoformat(
                        item[0].replace("Z", "+00:00")
                    ),
                    reverse=True,
                )
                result_language[cwd] = [entry for _, entry in sorted_entries]
            result[language] = result_language
        self.output_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    def load_cwe_to_cwd_map(self) -> Dict[str, str]:
        """Load mapping from each CWE to its CWD identifier"""
        map_path = self.root / "cwd_to_cwe.json"
        if not map_path.exists():
            raise FileNotFoundError(map_path)
        cwd_map = json.loads(map_path.read_text(encoding="utf-8"))
        cwe_to_cwd: Dict[str, str] = {}
        for cwd, cwes in cwd_map.items():
            for cwe in cwes:
                existing = cwe_to_cwd.get(cwe)
                if existing and existing != cwd:
                    raise ValueError(f"CWE {cwe} is mapped to both {existing} and {cwd}")
                cwe_to_cwd[cwe] = cwd
        return cwe_to_cwd

    def write_target_counts(self) -> None:
        if not self.target_csv.exists():
            return
        with self.target_csv.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            fieldnames = list(reader.fieldnames or [])
            rows = list(reader)

        # Add 'count' column to fieldnames
        if "count" not in fieldnames:
            fieldnames.append("count")

        with self.target_counts_copy.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                cwe = row.get("CWE", "").strip()
                row["count"] = self.counts.get(cwe, 0)
                writer.writerow(row)

    def log_progress(self, message: str) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = f"[{timestamp}] {message}"
        print(entry)
        with self.progress_log.open("a", encoding="utf-8") as fh:
            fh.write(entry + "\n")


def main() -> None:
    crawler = GithubCweCrawler()
    crawler.run()


if __name__ == "__main__":
    main()
