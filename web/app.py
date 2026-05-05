import json
import subprocess
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from pydantic import BaseModel

app = FastAPI(title="FHE Password Breach Detection")
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

# 빌드된 C++ 바이너리 경로 (프로젝트 루트 기준)
BINARY = Path(__file__).parent.parent / "build" / "fhe_pwd"


class PasswordRequest(BaseModel):
    password: str


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.post("/check")
async def check(req: PasswordRequest):
    if not BINARY.exists():
        raise HTTPException(status_code=500, detail="바이너리가 없습니다. 먼저 cmake --build build 를 실행하세요.")

    # C++ 바이너리 호출 (stdout: JSON, stderr: 진행 로그)
    proc = subprocess.run(
        [str(BINARY), req.password],
        capture_output=True,
        text=True,
        timeout=120,
    )

    # stdout 마지막 줄에서 JSON 파싱 (바이너리 로그와 분리)
    stdout_lines = [l for l in proc.stdout.strip().splitlines() if l.startswith("{")]
    if not stdout_lines:
        raise HTTPException(status_code=500, detail="바이너리 출력 파싱 실패")

    data = json.loads(stdout_lines[-1])
    return {
        "subtraction": {
            "leaked": data["sub_result"] >= 0,
            "index":  data["sub_result"],
            "ms":     round(data["sub_ms"], 2),
        },
        "fermat": {
            "leaked": data["fermat_result"] >= 0,
            "index":  data["fermat_result"],
            "ms":     round(data["fermat_ms"], 2),
        },
        "match": data["sub_result"] == data["fermat_result"],
    }
