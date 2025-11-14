# GitHub CWE Crawler

## Project Overview

GitHub CWE Crawler reads the CWE list in `target.csv`, runs GitHub searches plus AI-generated queries, and uses AI validation to keep only PRs that truly fix the target vulnerability. Every API response is cached under `response/`, each accepted record is appended to `response/records/`, and `github_cwe_results.json` is updated incrementally so you can pause/resume at any time without losing progress.

## Usage

1. **Prepare `target.csv`**
   - Add every CWE you want to crawl under a `CWE` column (and optionally `description` so AI keyword generation has context).
   - The crawler walks this file top-to-bottom, so trimming it to a few rows is the easiest way to run a smoke test.

2. **Provide credentials in `.env`**
   - Copy `.env.example` (if present) or create `.env` with at least `GITHUB_API_KEY=<your token>`.
   - Optional OpenAI-related values: `API_BASE_URL`, `API_KEY`, `MODEL_NAME`, `META_MODEL_NAME`.

3. **Manage dependencies with `uv`**
   - Install deps once with `uv sync` (creates `.venv/` in place). Use `uv add` if you need new packages.
   - Activate the environment (`source .venv/bin/activate`) for ad‑hoc commands, or rely on `uv run …` to launch tools inside the venv automatically.

4. **Run the crawler**
   - Kick off a crawl with `uv run python main.py`.
   - Logs stream to stdout and `response/progress.log`. Intermediate API payloads land under `response/<CWE>/…`.

5. **What the script does**
   - For each CWE in `target.csv`, run GitHub searches (direct `CWE-XXX` mentions plus AI-generated keywords).
   - Skip repositories with ≤100 stars and PRs already cached in `response/<CWE>/` or `response/records/<CWE>.jsonl`.
   - Fetch PR + file metadata (reusing cached JSON when present), summarize patches, and ask the AI validator whether the change truly fixes that CWE.
   - If accepted, choose the primary vulnerable file, extract before/after snippets, append a record to `response/records/<CWE>.jsonl`, and immediately merge it into `github_cwe_results.json` (sorted by `merged_at`).
   - Resume-friendly: rerunning the script only hits GitHub for new PRs and keeps appending to JSONL/JSON outputs.
