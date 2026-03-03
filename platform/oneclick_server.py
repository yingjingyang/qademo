"""FastAPI server exposing one-click audit endpoints for external platforms."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

# Reuse the in-workspace Skill implementation
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from skills.agent-audit.scripts.audit_scan import (  # noqa: E402
    DEFAULT_OUTPUT,
    generate_report,
    save_report,
    to_markdown,
)

DEFAULT_MARKDOWN = DEFAULT_OUTPUT.with_suffix(".md")


class AuditOptions(BaseModel):
    save_json: bool = False
    save_markdown: bool = False
    json_path: Optional[str] = None
    markdown_path: Optional[str] = None


app = FastAPI(
    title="Agent Audit Platform Server",
    description="Expose the local audit scanner over HTTP so an external platform可以一键触发体检。",
)


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/audit")
async def run_audit(options: AuditOptions | None = None) -> dict[str, object]:
    opts = options or AuditOptions()
    report = generate_report()
    response: dict[str, object] = {"report": report}

    if opts.save_json:
        json_path = Path(opts.json_path).expanduser() if opts.json_path else DEFAULT_OUTPUT
        save_report(report, json_path)
        response["jsonPath"] = str(json_path)

    if opts.save_markdown:
        markdown_path = (
            Path(opts.markdown_path).expanduser()
            if opts.markdown_path
            else DEFAULT_MARKDOWN
        )
        markdown_path.write_text(to_markdown(report))
        response["markdownPath"] = str(markdown_path)

    response["markdown"] = to_markdown(report)
    return response


@app.post("/audit/plain")
async def run_plain() -> dict[str, str]:
    report = generate_report()
    return {"markdown": to_markdown(report)}
