"""Create local case and immutable evidence metadata tables.

Revision ID: 0001_phase2
Revises: none
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_phase2"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("claim", sa.Text(), nullable=True),
        sa.Column("privacy_mode", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.PrimaryKeyConstraint("case_id"),
    )
    op.create_table(
        "evidence_blobs",
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("sha512", sa.String(length=128), nullable=False),
        sa.Column("byte_length", sa.BigInteger(), nullable=False),
        sa.Column("detected_mime_type", sa.String(length=127), nullable=False),
        sa.Column("storage_uri", sa.String(length=2048), nullable=False),
        sa.Column("object_version", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.PrimaryKeyConstraint("sha256"),
    )
    op.create_table(
        "evidence_assets",
        sa.Column("evidence_id", sa.String(length=36), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("blob_sha256", sa.String(length=64), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("client_mime_type", sa.String(length=127), nullable=True),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["blob_sha256"], ["evidence_blobs.sha256"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.case_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("evidence_id"),
        sa.UniqueConstraint("case_id", "blob_sha256", name="uq_evidence_case_blob"),
    )


def downgrade() -> None:
    op.drop_table("evidence_assets")
    op.drop_table("evidence_blobs")
    op.drop_table("cases")
