"""enable citext extension

Revision ID: 896b4cd9dee2
Revises: dbf774098fd5
Create Date: 2026-07-16 13:42:59.858703

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '896b4cd9dee2'
down_revision: Union[str, Sequence[str], None] = 'dbf774098fd5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP EXTENSION IF EXISTS citext")
