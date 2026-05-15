"""v2.4 outbound webhooks

Revision ID: 002_v24_webhooks
Revises: 001_v24_multitenant
Create Date: 2026-05-16
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "002_v24_webhooks"
down_revision: Union[str, None] = "001_v24_multitenant"
branch_labels = None
depends_on = None

def upgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())

    if "webhook_subscriptions" not in tables:
        op.create_table(
            "webhook_subscriptions",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("tenant_id", sa.String(length=64), nullable=False,
                      server_default="default"),
            sa.Column("name", sa.String, nullable=False),
            sa.Column("target_url", sa.String, nullable=False),
            sa.Column("secret", sa.String, server_default=""),
            sa.Column("event_filters", sa.JSON, nullable=False),
            sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("1")),
            sa.Column("max_attempts", sa.Integer, nullable=False, server_default="6"),
            sa.Column("created_by", sa.String, server_default=""),
            sa.Column("created_at", sa.DateTime, nullable=False,
                      server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime, nullable=False,
                      server_default=sa.func.now()),
        )
        op.create_index("ix_webhook_subscriptions_tenant_id",
                        "webhook_subscriptions", ["tenant_id"])

    if "webhook_deliveries" not in tables:
        op.create_table(
            "webhook_deliveries",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("tenant_id", sa.String(length=64), nullable=False,
                      server_default="default"),
            sa.Column("subscription_id", sa.Integer,
                      sa.ForeignKey("webhook_subscriptions.id"), nullable=False),
            sa.Column("delivery_uuid", sa.String, nullable=False, unique=True),
            sa.Column("event_type", sa.String, nullable=False),
            sa.Column("entity_type", sa.String, server_default=""),
            sa.Column("entity_id", sa.String, server_default=""),
            sa.Column("payload", sa.JSON, nullable=False),
            sa.Column("status", sa.String, nullable=False, server_default="pending"),
            sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
            sa.Column("response_code", sa.Integer, nullable=True),
            sa.Column("response_body", sa.Text, server_default=""),
            sa.Column("last_error", sa.Text, server_default=""),
            sa.Column("next_attempt_at", sa.DateTime, nullable=True),
            sa.Column("created_at", sa.DateTime, nullable=False,
                      server_default=sa.func.now()),
            sa.Column("delivered_at", sa.DateTime, nullable=True),
        )
        op.create_index("ix_webhook_deliveries_tenant_id",
                        "webhook_deliveries", ["tenant_id"])
        op.create_index("ix_webhook_deliveries_subscription_id",
                        "webhook_deliveries", ["subscription_id"])
        op.create_index("ix_webhook_deliveries_status",
                        "webhook_deliveries", ["status"])
        op.create_index("ix_webhook_deliveries_next_attempt_at",
                        "webhook_deliveries", ["next_attempt_at"])

def downgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "webhook_deliveries" in tables:
        for idx in (
            "ix_webhook_deliveries_tenant_id",
            "ix_webhook_deliveries_subscription_id",
            "ix_webhook_deliveries_status",
            "ix_webhook_deliveries_next_attempt_at",
        ):
            try:
                op.drop_index(idx, table_name="webhook_deliveries")
            except Exception:
                pass
        op.drop_table("webhook_deliveries")
    if "webhook_subscriptions" in tables:
        try:
            op.drop_index("ix_webhook_subscriptions_tenant_id",
                          table_name="webhook_subscriptions")
        except Exception:
            pass
        op.drop_table("webhook_subscriptions")
