# GitHub CWE 爬虫

## 项目介绍

脚本会读入 `target.csv` 中的 CWE 列表，结合 GitHub 搜索与 AI 关键词寻找修复 PR，通过 AI 判定是否与指定 CWE 匹配，并把补丁上下文写入 `response/records/*.jsonl` 与 `github_cwe_results.json`。全部 API 响应缓存在 `response/<CWE>/`，便于断点续跑与增量更新。

## 使用说明

1. **准备 `target.csv`**
   - 在 `CWE` 列中写入需要爬取的 CWE（可选的 `description` 列能提升 AI 生成关键词的效果）。
   - 按行顺序依次处理，快速试跑可以先保留少量 CWE。

2. **配置 `.env`**
   - 新建 `.env`（或复制示例）并写入 `GITHUB_API_KEY=<你的 token>`。
   - 若需自定义 AI 服务，可设置 `API_BASE_URL`、`API_KEY`、`MODEL_NAME`、`META_MODEL_NAME`。

3. **用 `uv` 管理环境**
   - 执行 `uv sync` 安装依赖并生成 `.venv/`；新增依赖时使用 `uv add ...`。
   - 通过 `source .venv/bin/activate` 手动激活虚拟环境，或直接使用 `uv run ...` 在虚拟环境内执行命令。

4. **运行爬虫**
   - 使用 `uv run python main.py` 启动。
   - 实时日志会打印到终端并写入 `response/progress.log`；每个请求的响应保存在 `response/<CWE>/...json`。

5. **核心流程**
   - 逐个 CWE 进行 GitHub 搜索（直接搜索 + AI 关键词搜索），并跳过 Star ≤ 100 的仓库。
   - 若 PR/文件响应已缓存或记录在 `response/records/<CWE>.jsonl`，则会自动跳过。
   - 对新 PR 获取详情与文件 diff，向 AI 校验是否确实修复对应 CWE。
   - 通过校验后提取关键文件的补丁片段，追加写入 `response/records/<CWE>.jsonl`，并增量更新 `github_cwe_results.json`（按合并时间倒序）。
   - 支持断点续跑：再次执行只会处理新的 PR。
