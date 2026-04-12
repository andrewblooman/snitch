from fastapi import APIRouter

from app.api.v1 import applications, cicd_scans, findings, github, remediation, reports, scans, seed

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(applications.router)
api_router.include_router(findings.router)
api_router.include_router(scans.router)
api_router.include_router(remediation.router)
api_router.include_router(reports.router)
api_router.include_router(seed.router)
api_router.include_router(github.router)
api_router.include_router(cicd_scans.router)
