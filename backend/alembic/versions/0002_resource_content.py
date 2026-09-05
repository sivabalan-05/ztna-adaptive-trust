"""resource content

Revision ID: 0002_resource_content
Revises: 0001_initial
Create Date: 2026-09-05

Adds the file-content columns to ``resources``. Every column is nullable so
existing rows migrate untouched; a resource with no file is still valid.
"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_resource_content"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SQLite cannot ALTER a table to add a constraint, so the foreign key has
    # to be created inside a batch operation that rebuilds the table.
    with op.batch_alter_table("resources") as batch:
        batch.add_column(sa.Column("file_name", sa.String(length=255), nullable=True))
        batch.add_column(sa.Column("file_path", sa.String(length=512), nullable=True))
        batch.add_column(sa.Column("content_type", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("file_size", sa.Integer(), nullable=True))
        batch.add_column(
            sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(sa.Column("uploaded_by_id", sa.Uuid(), nullable=True))
        batch.create_foreign_key(
            "fk_resources_uploaded_by_id_users",
            "users",
            ["uploaded_by_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("resources") as batch:
        batch.drop_constraint("fk_resources_uploaded_by_id_users", type_="foreignkey")
        batch.drop_column("uploaded_by_id")
        batch.drop_column("uploaded_at")
        batch.drop_column("file_size")
        batch.drop_column("content_type")
        batch.drop_column("file_path")
        batch.drop_column("file_name")
