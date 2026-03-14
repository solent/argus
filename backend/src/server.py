import asyncio
from datetime import datetime, timezone
import json
import os
import sys
import uuid
import zipfile
import tempfile
import traceback
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import asdict
sys.path.append(str(Path(__file__).parent))

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from classes.ProjectInfos import ProjectInfos, TestResult
from classes.config import (
    OPENROUTER_API_KEY, MODEL_NAME, get_openrouter_models,
    JUDGE_MODELS, ON_PREMISE_MODEL,
    ON_PREMISE_BASE_URL, ON_PREMISE_API_KEY,
)
import databases
import sqlalchemy
from classes.config import Config
from classes.Model import Model

# --- DB setup ---
DATABASE_URL = "sqlite:////data/test_results.db"

# Ensure the data directory exists (in case the volume is not mounted)
os.makedirs("/data", exist_ok=True)

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

test_results = sqlalchemy.Table(
    "test_results",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, primary_key=True),
    sqlalchemy.Column("data", sqlalchemy.JSON, nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.String, nullable=False),
)

engine = sqlalchemy.create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)
metadata.create_all(engine)


# =========================
# Imports pipeline
# =========================

from classes.CallGraphNode import CallGraphNode

if not OPENROUTER_API_KEY:
    raise ValueError("OPENROUTER_API_KEY not set")


# =========================
# Utils
# =========================

def _serialize(obj):
    """Convertit les objets non JSON-serializables en chaîne"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def _to_json_dict(obj) -> dict:
    """Serialise un dataclass en dict JSON-compatible."""
    raw = asdict(obj)
    json_str = json.dumps(raw, default=_serialize, indent=2)
    return json.loads(json_str)


# =========================
# Pipeline helpers
# =========================

async def _reset_call_graph_state():
    """Réinitialise les attributs statiques de CallGraphNode entre deux analyses."""
    CallGraphNode._initialized = False
    CallGraphNode._library_tasks = []
    CallGraphNode._functions = {}
    CallGraphNode._calls = {}
    CallGraphNode._visited = {}
    # _libraries n'est pas un ClassVar déclaré dans CallGraphNode mais était
    # présent dans l'original — on le remet par sécurité.
    if hasattr(CallGraphNode, "_libraries"):
        CallGraphNode._libraries = {}


async def _await_library_tasks():
    """Attend toutes les tâches async de résolution de librairies."""
    if CallGraphNode._library_tasks:
        await asyncio.gather(*CallGraphNode._library_tasks)
    CallGraphNode._library_tasks = []


async def generate_ai_report(
    projectInfos: ProjectInfos,
    selectedNode: CallGraphNode = None,
) -> Dict:
    """
    Génère un rapport IA global ou ciblé (sur selectedNode).
    Retourne un dict JSON-compatible pour FastAPI.
    """
    if selectedNode:
        await projectInfos.call_graph.generate_targeted_ai_report(selectedNode)
    else:
        await projectInfos.call_graph.generate_global_ai_report()

    return _to_json_dict(projectInfos)


async def analyzeCppProject(project_dir: str) -> Dict:
    await _reset_call_graph_state()

    project = ProjectInfos(project_dir)

    await _await_library_tasks()

    return _to_json_dict(project)


async def testCppProject(
    project_dir: str,
    testedModel: str,
    judgeModels: List[str],
) -> TestResult:
    print("[INFO] Starting testCppProject")

    await _reset_call_graph_state()
    print("[INFO] Static reset done")

    print(f"[INFO] Constructing ProjectInfos for {project_dir}")
    project = ProjectInfos(project_dir)
    print("[INFO] ProjectInfos constructed")

    await _await_library_tasks()
    print("[INFO] Library tasks completed")

    print(f"[INFO] Retrieving tested model '{testedModel}'")
    testModel = Config.models.get(testedModel)
    if not testModel:
        raise ValueError(f"[ERROR] Tested model '{testedModel}' not found in config")
    print(f"[INFO] Tested model '{testedModel}' retrieved")

    print("[INFO] Generating global AI report")
    await project.call_graph.generate_global_ai_report(testModel)
    print("[INFO] Global AI report generation completed")

    judgeModelsObjs = []
    for judgeModelName in judgeModels:
        print(f"[INFO] Retrieving judge model '{judgeModelName}'")
        judgeModel = Config.models.get(judgeModelName)
        if not judgeModel:
            raise ValueError(f"[ERROR] Judge model '{judgeModelName}' not found in config")
        judgeModelsObjs.append(judgeModel)

    print("[INFO] Judging AI report")
    await project.call_graph.judge_ai_report(judgeModelsObjs)
    print("[INFO] AI report judged successfully")

    testResult = TestResult(
        id=str(uuid.uuid4()),
        created_at=datetime.now(timezone.utc).isoformat(),
        tested_model=testedModel,
        project=project,
    )
    print("[INFO] testCppProject completed successfully")
    return testResult


# =========================
# FastAPI server
# =========================

app = FastAPI()

origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "https://ast-analyzer-531057961347.europe-west1.run.app",
    "https://www.neo-imt.cloud",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    await database.connect()
    Config.models = get_openrouter_models(OPENROUTER_API_KEY, limit=10)

    # Re-init on-premise model with runtime env vars (overrides class-level defaults)
    Config.model_local = Model(
        name=ON_PREMISE_MODEL,
        api_key=ON_PREMISE_API_KEY,
        base_url=ON_PREMISE_BASE_URL,
    )
    Config.model_on_premise = Config.model_local   # keep backward-compat alias in sync

    # Always register the on-premise model in the catalogue so the Test module
    # can find it via Config.models.get(ON_PREMISE_MODEL).
    # get_openrouter_models() only fetches from OpenRouter — a local Ollama model
    # (e.g. devstral:24b on Solent) is never returned by that call, which caused
    # testModels to be empty and testCppProject to raise "model not found".
    Config.models[ON_PREMISE_MODEL] = Config.model_local


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


# =========================
# Routes
# =========================

@app.post("/analyze")
async def analyze(project: UploadFile = File(...)):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "project.zip")
            with open(zip_path, "wb") as f:
                f.write(await project.read())
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(tmpdir)

            result = await analyzeCppProject(tmpdir)
            return JSONResponse(result)

    except Exception as e:
        traceback.print_exc()
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/llm_generate_report")
async def llm_generate_report(
    project: UploadFile = File(...),
    projectInfos: str = Form(...),
    selectedNode: Optional[str] = Form(None),
):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "project.zip")
            with open(zip_path, "wb") as f:
                f.write(await project.read())
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(tmpdir)

            projectInfos_obj = ProjectInfos.from_dict(json.loads(projectInfos), Path(tmpdir))
            selected = (
                CallGraphNode.from_dict(json.loads(selectedNode), Path(tmpdir))
                if selectedNode
                else None
            )

            result = await generate_ai_report(projectInfos_obj, selectedNode=selected)
            return JSONResponse(result)

    except Exception as e:
        traceback.print_exc()
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/test_results")
async def get_test_results():
    query = test_results.select()
    rows = await database.fetch_all(query)

    results_dict = {r["id"]: r["data"] for r in rows}

    # testModels  → small / cheap models meant to be evaluated
    test_model_ids  = {ON_PREMISE_MODEL}
    # judgeModels → strong models used as ground-truth judges
    judge_model_ids = set(JUDGE_MODELS)

    available = set(Config.models.keys())

    return {
        "results":     results_dict,
        "testModels":  sorted(available & test_model_ids),
        "judgeModels": sorted(available & judge_model_ids),
    }


@app.post("/test_results")
async def add_test_result(
    project: UploadFile = File(...),
    testedModel: str = Form(...),
    judgeModels: List[str] = Form(...),
):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "project.zip")
            with open(zip_path, "wb") as f:
                f.write(await project.read())
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(tmpdir)

            tr = await testCppProject(tmpdir, testedModel, judgeModels)

            data_dict = _to_json_dict(tr)

            # BUG FIX 1: insert() ne retourne pas la ligne insérée → utiliser
            # execute() pour l'insert, puis select() pour relire.
            insert_query = test_results.insert().values(
                id=tr.id,
                data=data_dict,
                created_at=tr.created_at,
            )
            await database.execute(insert_query)

            # BUG FIX 2: relire la ligne fraîchement insérée
            select_query = test_results.select().where(test_results.c.id == tr.id)
            row = await database.fetch_one(select_query)
            if not row:
                raise HTTPException(status_code=500, detail="Insert succeeded but row not found")

            return JSONResponse(row["data"])

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/test_results/{tr_id}")
async def get_test_result(tr_id: str):
    query = test_results.select().where(test_results.c.id == tr_id)
    row = await database.fetch_one(query)
    if not row:
        raise HTTPException(status_code=404, detail="TestResult not found")

    # BUG FIX 3: la donnée est dans row["data"], pas dans row directement
    return JSONResponse(row["data"])