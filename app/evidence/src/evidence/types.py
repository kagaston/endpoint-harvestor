from pydantic import BaseModel, Field


class ManifestEntry(BaseModel):
    file_path: str
    sha256: str
    size_bytes: int
    collected_at: str


class AuditEvent(BaseModel):
    timestamp: str
    action: str
    component: str
    detail: str = ""
    success: bool = True


class ChainOfCustody(BaseModel):
    case_id: str = ""
    examiner: str = ""
    tool_name: str = "IntrusionInspector"
    tool_version: str = "0.1.0"
    hostname: str = ""
    os_info: str = ""
    collection_start: str = ""
    collection_end: str = ""
    manifest_sha256: str = ""
    total_artifacts: int = 0
    total_files: int = 0
    notes: str = ""
