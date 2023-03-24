"""init

Revision ID: 11cfd787a323
Revises: 
Create Date: 2023-03-23 23:39:06.730452

"""
from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision = '11cfd787a323'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # create tables for Category and Clue models
    op.create_table('subscribers',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('user_name', sa.String(), nullable=False),
        sa.Column('is_gifted', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('subscribers')
