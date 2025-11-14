# GitHub CWE Crawl Plan (Revised)

## Goal
Use the GitHub REST API (tokens from `.env`) to collect merged PRs/commits referencing each CWE in `target.csv`, satisfying:
1. Repo stars > 1k.
2. Merged PR with commit URL.
3. PR touches exactly one file.
4. Repo has a tag or discussion explicitly mentioning the same CWE.
5. Results sorted newest → oldest per CWE, capped at 1000 entries.
6. Raw responses saved under `response/`; final output matches `example.jsonc` with `source: "github"`.
7. After crawling, duplicate `target.csv` and append per-CWE counts to the end.
8. Keep memory usage low via streaming/iterative processing (avoid loading huge datasets at once).

## Approach
1. **Preparation**
   - Parse `target.csv` iteratively (line-by-line) to obtain CWE list.
   - Load tokens/config from `.env`. Ensure tooling uses uv-managed `.venv`.
   - Organize output dirs (`response/{cwe}`) lazily to avoid unnecessary allocations.

2. **Candidate Discovery (Streaming)**
   - For each CWE, query GitHub Search Issues API with `is:pr is:merged "CWE-xxx"`.
   - Process paginated results one page at a time, persisting minimal metadata before moving on.

3. **Repository Validation**
   - For each candidate repo, fetch repo info to verify stars ≥ 1000.
   - Stream through tags/discussions endpoints (page at a time) until finding a CWE mention; discard repo otherwise.

4. **PR Filtering & Data Extraction**
   - Fetch PR details and `/files` listing, ensuring exactly one file changed.
   - Retrieve associated commits/patch info as needed, streaming per PR.
   - Store raw JSON under `response/{cwe}/...` immediately after fetching to avoid in-memory buildup.

5. **Record Assembly**
   - As each valid PR is confirmed, transform directly into the JSONC entry structure and append to an on-disk accumulator (e.g., write per-CWE partial files or use incremental JSON serialization) to minimize memory usage.
   - Track counts per CWE incrementally during processing.

6. **Output Generation**
   - Combine per-CWE records (already stored on disk) newest→oldest using timestamps recorded during streaming.
   - Ensure each entry includes `commit_url`, `issue_url`, code snippets, and `source: "github"`.

7. **Post-processing**
   - Duplicate `target.csv` to a new file (e.g., `target_with_counts.csv`) and append lines summarizing each CWE and the count of collected snippets.
   - Document CWEs with zero findings.

8. **Verification**
   - Spot-check several entries for criteria compliance.
   - Confirm raw responses exist and counts in the duplicated CSV match collected data.
