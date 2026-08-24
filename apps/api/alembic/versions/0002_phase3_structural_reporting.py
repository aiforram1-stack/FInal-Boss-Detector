"""Persist structural analysis runs, tests, artifacts, and reports.

Revision ID: 0002_phase3
Revises: 0001_phase2
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_phase3"
down_revision: str | None = "0001_phase2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "structural_analysis_runs",
        sa.Column("analysis_run_id", sa.String(length=36), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("evidence_id", sa.String(length=36), nullable=False),
        sa.Column("analysis_profile", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("input_sha256", sa.String(length=64), nullable=False),
        sa.Column("software_version", sa.String(length=255), nullable=False),
        sa.Column("git_commit", sa.String(length=40), nullable=True),
        sa.Column("started_at", sa.String(length=40), nullable=False),
        sa.Column("completed_at", sa.String(length=40), nullable=True),
        sa.Column("terminal_json", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["case_id"], ["cases.case_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evidence_id"], ["evidence_assets.evidence_id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("analysis_run_id"),
    )
    op.create_index(
        "uq_structural_active_evidence_profile",
        "structural_analysis_runs",
        ["evidence_id", "analysis_profile"],
        unique=True,
        sqlite_where=sa.text("status = 'RUNNING'"),
    )
    op.create_table(
        "structural_test_results",
        sa.Column("result_id", sa.String(length=36), nullable=False),
        sa.Column("analysis_run_id", sa.String(length=36), nullable=False),
        sa.Column("test_id", sa.String(length=255), nullable=False),
        sa.Column("test_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("tool_name", sa.String(length=255), nullable=True),
        sa.Column("tool_version", sa.String(length=500), nullable=True),
        sa.Column("runtime_ms", sa.BigInteger(), nullable=True),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["analysis_run_id"],
            ["structural_analysis_runs.analysis_run_id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("result_id"),
        sa.UniqueConstraint("analysis_run_id", "test_id", name="uq_structural_run_test"),
    )
    op.create_table(
        "structural_artifacts",
        sa.Column("artifact_id", sa.String(length=36), nullable=False),
        sa.Column("analysis_run_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=100), nullable=False),
        sa.Column("storage_uri", sa.String(length=2048), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("byte_length", sa.BigInteger(), nullable=False),
        sa.Column("mime_type", sa.String(length=127), nullable=False),
        sa.Column("tool_source", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["analysis_run_id"],
            ["structural_analysis_runs.analysis_run_id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("artifact_id"),
        sa.UniqueConstraint("storage_uri"),
    )
    op.create_table(
        "structural_reports",
        sa.Column("report_id", sa.String(length=36), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("analysis_run_id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("evidence_id", sa.String(length=36), nullable=False),
        sa.Column("report_json_uri", sa.String(length=2048), nullable=False),
        sa.Column("report_json_sha256", sa.String(length=64), nullable=False),
        sa.Column("report_json_bytes", sa.BigInteger(), nullable=False),
        sa.Column("report_html_uri", sa.String(length=2048), nullable=False),
        sa.Column("report_html_sha256", sa.String(length=64), nullable=False),
        sa.Column("report_html_bytes", sa.BigInteger(), nullable=False),
        sa.Column("manifest_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["analysis_run_id"],
            ["structural_analysis_runs.analysis_run_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.case_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evidence_id"], ["evidence_assets.evidence_id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("report_id"),
        sa.UniqueConstraint("analysis_run_id"),
    )


def downgrade() -> None:
    op.drop_table("structural_reports")
    op.drop_table("structural_artifacts")
    op.drop_table("structural_test_results")
    op.drop_index("uq_structural_active_evidence_profile", table_name="structural_analysis_runs")
    op.drop_table("structural_analysis_runs")
