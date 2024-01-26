# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from juju.errors import JujuError
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

APPLICATION_NAME = "tls-constraints"


class TestTLSConstraintsOperator:
    @pytest.fixture(scope="module")
    @pytest.mark.abort_on_fail
    async def charm(self, ops_test):
        ops_test.destructive_mode = False
        charm = await ops_test.build_charm(".")
        return charm

    @pytest.fixture()
    async def cleanup(self, ops_test):
        try:
            await ops_test.model.remove_application(
                app_name=APPLICATION_NAME, block_until_done=True
            )
        except JujuError:
            pass

    async def test_given_charm_when_deploy_then_status_is_active(
        self, ops_test: OpsTest, charm, cleanup
    ):
        assert ops_test.model
        await ops_test.model.deploy(
            entity_url=charm,
            application_name=APPLICATION_NAME,
            series="jammy",
        )

        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)
