from __future__ import annotations

import uuid

from app.models.role import Role
from app.repositories.role_repository import RoleRepository


class TestRoleRepository:
    def test_get_by_name_finds_an_existing_role(self, db_session):
        role_name = f"buyer-{uuid.uuid4()}"
        role = Role(name=role_name, description="Can browse and purchase properties")
        db_session.add(role)
        db_session.flush()

        repo = RoleRepository(db_session)
        found = repo.get_by_name(role_name)

        assert found is not None
        assert found.id == role.id

    def test_get_by_name_returns_none_for_unknown_role(self, db_session):
        repo = RoleRepository(db_session)

        found = repo.get_by_name("this-role-does-not-exist")

        assert found is None

    def test_get_by_id_finds_an_existing_role(self, db_session):
        role = Role(name=f"agent-{uuid.uuid4()}")
        db_session.add(role)
        db_session.flush()

        repo = RoleRepository(db_session)
        found = repo.get_by_id(role.id)

        assert found is not None
        assert found.name == role.name

    def test_get_by_id_returns_none_for_unknown_id(self, db_session):
        repo = RoleRepository(db_session)

        found = repo.get_by_id(uuid.uuid4())

        assert found is None
