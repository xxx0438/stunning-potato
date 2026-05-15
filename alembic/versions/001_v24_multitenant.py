"""v2.4 multi-tenancy + jwt + hashchain + idempotency

Revision ID: 001_v24
Revises:
"""
import sqlalchemy as sa
from alembic import op

revision = "001_v24"
down_revision = None
branch_labels = None
depends_on = None

TENANT_AWARE = [
    "assets", "asset_versions", "execution_logs", "change_requests",
    "integration_connections", "external_references", "integration_events",
    "telemetry_outbox", "observability_incidents",
    "review_requests", "review_assignments", "comments", "activity_events",
    "collaboration_tasks", "edit_locks", "evaluation_suites", "evaluation_runs",
]

def _has_col(inspector, table, col):
    return col in {c["name"] for c in inspector.get_columns(table)}

def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    for t in TENANT_AWARE:
        if t in tables and not _has_col(inspector, t, "tenant_id"):
            op.add_column(t, sa.Column("tenant_id", sa.String(64), nullable=False, server_default="default"))
            op.create_index(f"ix_{t}_tenant_id", t, ["tenant_id"])

    # comments.idempotency_key
    if "comments" in tables and not _has_col(inspector, "comments", "idempotency_key"):
        op.add_column("comments", sa.Column("idempotency_key", sa.String, nullable=True))
        op.create_index("ix_comments_idempotency_key", "comments", ["idempotency_key"])

    # evaluation_runs.mode
    if "evaluation_runs" in tables and not _has_col(inspector, "evaluation_runs", "mode"):
        op.add_column("evaluation_runs", sa.Column("mode", sa.String, nullable=False, server_default="stub"))

    # activity_events hash chain
    if "activity_events" in tables:
        if not _has_col(inspector, "activity_events", "prev_hash"):
            op.add_column("activity_events", sa.Column("prev_hash", sa.String(64), nullable=True))
            op.create_index("ix_activity_events_prev_hash", "activity_events", ["prev_hash"])
        if not _has_col(inspector, "activity_events", "hash_value"):
            op.add_column("activity_events", sa.Column("hash_value", sa.String(64), nullable=True))
            op.create_index("ix_activity_events_hash_value", "activity_events", ["hash_value"])

    # user_tenant_memberships
    if "user_tenant_memberships" not in tables:
        op.create_table(
            "user_tenant_memberships",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
            sa.Column("tenant_id", sa.String(64), nullable=False),
            sa.Column("roles", sa.JSON, nullable=False),
            sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("user_id", "tenant_id", name="uq_user_tenant"),
        )
        op.create_index("ix_user_tenant_memberships_user_id", "user_tenant_memberships", ["user_id"])
        op.create_index("ix_user_tenant_memberships_tenant_id", "user_tenant_memberships", ["tenant_id"])

    # Asset 唯一索引调整
    if "assets" in tables:
        try:
            op.drop_constraint("uq_asset_namespace_name", "assets", type_="unique")
        except Exception:
            pass
        try:
            op.create_unique_constraint("uq_asset_tenant_ns_name", "assets",
                                         ["tenant_id", "namespace", "name"])
        except Exception:
            pass

def downgrade() -> None:
    op.drop_table("user_tenant_memberships")
    for t in TENANT_AWARE:
        try:
            op.drop_index(f"ix_{t}_tenant_id", table_name=t)
            op.drop_column(t, "tenant_id")
        except Exception:
            pass
