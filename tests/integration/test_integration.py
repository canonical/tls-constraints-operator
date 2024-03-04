# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APPLICATION_NAME = METADATA["name"]

TLS_PROVIDER_CHARM_NAME = "self-signed-certificates"
TLS_REQUIRER_CHARM_NAME = "tls-certificates-requirer"
TLS_REQUIRER1 = f"{TLS_REQUIRER_CHARM_NAME}1"
TLS_REQUIRER2 = f"{TLS_REQUIRER_CHARM_NAME}2"


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test: OpsTest):
    """Build the charm-under-test and deploy it."""
    assert ops_test.model
    charm_build = asyncio.create_task(ops_test.build_charm("."))
    await ops_test.model.deploy(
        TLS_PROVIDER_CHARM_NAME,
        application_name=TLS_PROVIDER_CHARM_NAME,
        channel="edge",
    )
    await ops_test.model.deploy(
        TLS_REQUIRER_CHARM_NAME,
        application_name=TLS_REQUIRER1,
        channel="edge",
    )
    await ops_test.model.deploy(
        TLS_REQUIRER_CHARM_NAME,
        application_name=TLS_REQUIRER2,
        channel="edge",
    )
    charm = await charm_build
    await ops_test.model.deploy(
        charm,
        application_name=APPLICATION_NAME,
        series="jammy",
        trust=True,
    )


async def test_given_charm_is_not_related_to_provider_when_deploy_then_status_is_blocked(
    ops_test: OpsTest,
    build_and_deploy,
):
    assert ops_test.model
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=1000)


async def test_given_provider_is_related_then_status_is_active(
    ops_test: OpsTest,
    build_and_deploy,
):
    assert ops_test.model
    await ops_test.model.add_relation(
        relation1=f"{APPLICATION_NAME}:certificates-requires",
        relation2=TLS_PROVIDER_CHARM_NAME,
    )

    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)


async def test_given_tls_requirer1_is_deployed_and_related_then_certificate_is_created_and_passed_correctly(  # noqa: E501
    ops_test: OpsTest,
    build_and_deploy,
):
    assert ops_test.model
    await ops_test.model.add_relation(
        relation1=f"{APPLICATION_NAME}:certificates-provides", relation2=TLS_REQUIRER1
    )
    await ops_test.model.wait_for_idle(
        apps=[TLS_REQUIRER1],
        status="active",
        timeout=1000,
    )
    action_output = await run_get_certificate_action(ops_test, TLS_REQUIRER1)
    assert action_output["certificate"] is not None
    assert action_output["ca-certificate"] is not None
    assert action_output["csr"] is not None


async def test_given_tls_requirer2_is_deployed_and_related_then_certificate_is_created_passed_correctly_and_different(  # noqa: E501
    ops_test: OpsTest,
    build_and_deploy,
):
    assert ops_test.model
    await ops_test.model.add_relation(
        relation1=f"{APPLICATION_NAME}:certificates-provides",
        relation2=TLS_REQUIRER2,
    )
    await ops_test.model.wait_for_idle(
        apps=[TLS_REQUIRER2],
        status="active",
        timeout=1000,
    )
    action_output2 = await run_get_certificate_action(ops_test, TLS_REQUIRER2)
    assert action_output2["certificate"] is not None
    assert action_output2["ca-certificate"] is not None
    assert action_output2["csr"] is not None

    action_output1 = await run_get_certificate_action(ops_test, TLS_REQUIRER1)
    assert action_output1["certificate"] != action_output2["certificate"]
    assert action_output1["csr"] != action_output2["csr"]


async def run_get_certificate_action(ops_test: OpsTest, app_name: str) -> dict:
    """Run `get-certificate` on the first unit of app_name.

    Args:
        ops_test (OpsTest): OpsTest
        app_name (str): Application Name to target

    Returns:
        dict: Action output
    """
    assert ops_test.model
    tls_requirer_unit = ops_test.model.units[f"{app_name}/0"]
    action = await tls_requirer_unit.run_action(
        action_name="get-certificate",
    )
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output
