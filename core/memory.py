"""Persistance des missions (SQLite/SQLAlchemy) et memoire semantique (ChromaDB).

Aucune dependance torch/sentence-transformers : les embeddings de ChromaDB
passent par l'endpoint /api/embeddings d'un conteneur Ollama deja present
pour le LLM principal (voir CLAUDE.md, section 8).
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

import httpx
from sqlalchemy import Column, String, Text, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

try:
    import chromadb
    from chromadb import EmbeddingFunction, Embeddings
except ImportError:  # pragma: no cover - chromadb optionnel pour les tests unitaires
    chromadb = None
    EmbeddingFunction = object
    Embeddings = list

from core.config import get_settings
from core.state import Finding, Lead, MissionState, Severity, Target


class Base(DeclarativeBase):
    pass


class MissionRow(Base):
    __tablename__ = "missions"

    mission_id: Any = Column(String, primary_key=True)
    mission_name: Any = Column(String, nullable=False)
    operator: Any = Column(String, nullable=False)
    data: Any = Column(Text, nullable=False)
    updated_at: Any = Column(String, nullable=False)


def mission_to_dict(mission: MissionState) -> dict[str, Any]:
    return {
        "mission_id": mission.mission_id,
        "mission_name": mission.mission_name,
        "operator": mission.operator,
        "authorization_ref": mission.authorization_ref,
        "target": {
            "host": mission.target.host,
            "ports": mission.target.ports,
            "services": mission.target.services,
            "os_guess": mission.target.os_guess,
            "os_confidence": mission.target.os_confidence,
        },
        "status": mission.status,
        "current_agent": mission.current_agent,
        "last_decision": mission.last_decision,
        "completed_phases": mission.completed_phases,
        "orchestration_cycles": mission.orchestration_cycles,
        "findings": [
            {
                "title": f.title,
                "severity": int(f.severity),
                "description": f.description,
                "affected_component": f.affected_component,
                "evidence": f.evidence,
                "discovered_by": f.discovered_by,
                "remediation": f.remediation,
                "cve": f.cve,
                "tags": f.tags,
                "exploited": f.exploited,
                "id": f.id,
                "created_at": f.created_at,
            }
            for f in mission.findings
        ],
        "leads": [
            {
                "title": l.title,
                "rationale": l.rationale,
                "source": l.source,
                "confidence": l.confidence,
                "tags": l.tags,
                "id": l.id,
                "created_at": l.created_at,
            }
            for l in mission.leads
        ],
        "attack_chain": mission.attack_chain,
        "tool_results": mission.tool_results,
        "errors": mission.errors,
        "report_path": mission.report_path,
        "created_at": mission.created_at,
        "updated_at": mission.updated_at,
    }


def mission_from_dict(data: dict[str, Any]) -> MissionState:
    target_data = data["target"]
    target = Target(
        host=target_data["host"],
        ports=target_data.get("ports", []),
        services={int(k): v for k, v in target_data.get("services", {}).items()},
        os_guess=target_data.get("os_guess"),
        os_confidence=target_data.get("os_confidence"),
    )
    mission = MissionState(
        mission_id=data["mission_id"],
        mission_name=data["mission_name"],
        operator=data["operator"],
        authorization_ref=data.get("authorization_ref"),
        target=target,
    )
    mission.status = data.get("status", "pending")
    mission.current_agent = data.get("current_agent")
    mission.last_decision = data.get("last_decision")
    mission.completed_phases = data.get("completed_phases", [])
    mission.orchestration_cycles = data.get("orchestration_cycles", 0)
    mission.findings = [
        Finding(
            title=f["title"],
            severity=Severity(f["severity"]),
            description=f["description"],
            affected_component=f["affected_component"],
            evidence=f["evidence"],
            discovered_by=f["discovered_by"],
            remediation=f.get("remediation", ""),
            cve=f.get("cve"),
            tags=f.get("tags", []),
            exploited=f.get("exploited", False),
            id=f.get("id"),
            created_at=f.get("created_at"),
        )
        for f in data.get("findings", [])
    ]
    mission.leads = [
        Lead(
            title=l["title"],
            rationale=l["rationale"],
            source=l["source"],
            confidence=l["confidence"],
            tags=l.get("tags", []),
            id=l.get("id"),
            created_at=l.get("created_at"),
        )
        for l in data.get("leads", [])
    ]
    mission.attack_chain = data.get("attack_chain", [])
    mission.tool_results = data.get("tool_results", [])
    mission.errors = data.get("errors", [])
    mission.report_path = data.get("report_path")
    mission.created_at = data.get("created_at", mission.created_at)
    mission.updated_at = data.get("updated_at", mission.updated_at)
    return mission


class MissionStore:
    """Source de verite persistee pour l'API et le dashboard (SQLAlchemy + aiosqlite)."""

    def __init__(self, db_path: str) -> None:
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def init(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def save(self, mission: MissionState) -> None:
        payload = json.dumps(mission_to_dict(mission))
        async with self._session_factory() as session:
            row = await session.get(MissionRow, mission.mission_id)
            if row is None:
                row = MissionRow(
                    mission_id=mission.mission_id,
                    mission_name=mission.mission_name,
                    operator=mission.operator,
                    data=payload,
                    updated_at=mission.updated_at,
                )
                session.add(row)
            else:
                row.data = payload
                row.updated_at = mission.updated_at
            await session.commit()

    async def get(self, mission_id: str) -> Optional[MissionState]:
        async with self._session_factory() as session:
            row = await session.get(MissionRow, mission_id)
        if row is None:
            return None
        return mission_from_dict(json.loads(row.data))

    async def list_all(self) -> list[MissionState]:
        async with self._session_factory() as session:
            result = await session.execute(select(MissionRow).order_by(MissionRow.updated_at.desc()))
            rows = result.scalars().all()
        return [mission_from_dict(json.loads(r.data)) for r in rows]


class OllamaEmbeddingFunction(EmbeddingFunction):
    """Embeddings via l'endpoint /api/embeddings d'Ollama, sans torch ni sentence-transformers."""

    def __init__(self, base_url: str, model: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model

    def __call__(self, input: list[str]) -> "Embeddings":  # noqa: A002 - nom impose par l'interface Chroma
        embeddings = []
        with httpx.Client(timeout=30) as client:
            for text in input:
                response = client.post(
                    f"{self._base_url}/api/embeddings",
                    json={"model": self._model, "prompt": text},
                )
                response.raise_for_status()
                embeddings.append(response.json()["embedding"])
        return embeddings


class SemanticMemory:
    """Memoire semantique ChromaDB pour retrouver un contexte de mission similaire."""

    def __init__(self) -> None:
        settings = get_settings()
        self._enabled = chromadb is not None
        if not self._enabled:
            return
        os.makedirs(settings.db_dir, exist_ok=True)
        self._client = chromadb.PersistentClient(path=settings.db_dir)
        embed_fn = OllamaEmbeddingFunction(settings.ollama_base_url, settings.ollama_embed_model)
        self._collection = self._client.get_or_create_collection(
            name="mission_memory", embedding_function=embed_fn
        )

    def add(self, mission_id: str, doc_id: str, text: str, metadata: dict[str, Any]) -> None:
        if not self._enabled:
            return
        self._collection.add(ids=[f"{mission_id}:{doc_id}"], documents=[text], metadatas=[metadata])

    def query(self, text: str, n_results: int = 5) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        result = self._collection.query(query_texts=[text], n_results=n_results)
        docs = result.get("documents", [[]])[0]
        metas = result.get("metadatas", [[]])[0]
        return [{"text": d, "metadata": m} for d, m in zip(docs, metas)]
