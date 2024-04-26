# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
import yaml
from juju.application import Application
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APPLICATION_NAME = METADATA["name"]

TLS_PROVIDER_CHARM_NAME = "self-signed-certificates"
TLS_REQUIRER_CHARM_NAME = "tls-certificates-requirer"
TLS_REQUIRER1 = f"{TLS_REQUIRER_CHARM_NAME}1"
TLS_REQUIRER2 = f"{TLS_REQUIRER_CHARM_NAME}2"
TLS_REQUIRER3 = f"{TLS_REQUIRER_CHARM_NAME}3"
TLS_REQUIRER4 = f"{TLS_REQUIRER_CHARM_NAME}4"
TLS_REQUIRER5 = f"{TLS_REQUIRER_CHARM_NAME}5"
RELATION_NAME_TO_TLS_REQUIRER = "certificates-downstream"
RELATION_NAME_TO_TLS_PROVIDER = "certificates-upstream"


@pytest.fixture(scope="module", autouse=True)
async def deploy(ops_test: OpsTest, request):
    """Deploy charm-under-test."""
    assert ops_test.model
    charm = Path(request.config.getoption("--charm_path")).resolve()
    await ops_test.model.deploy(
        TLS_PROVIDER_CHARM_NAME,
        application_name=TLS_PROVIDER_CHARM_NAME,
        channel="stable",
    )
    await ops_test.model.deploy(
        TLS_REQUIRER_CHARM_NAME,
        application_name=TLS_REQUIRER1,
        channel="stable",
    )
    await ops_test.model.deploy(
        TLS_REQUIRER_CHARM_NAME,
        application_name=TLS_REQUIRER2,
        channel="stable",
    )
    await ops_test.model.deploy(
        TLS_REQUIRER_CHARM_NAME,
        application_name=TLS_REQUIRER3,
        channel="stable",
    )
    await ops_test.model.deploy(
        TLS_REQUIRER_CHARM_NAME,
        application_name=TLS_REQUIRER4,
        channel="stable",
        config={"common_name": "reserved_name"},
    )
    await ops_test.model.deploy(
        TLS_REQUIRER_CHARM_NAME,
        application_name=TLS_REQUIRER5,
        channel="stable",
        config={"common_name": "reserved_name"},
    )
    await ops_test.model.deploy(
        charm,
        application_name=APPLICATION_NAME,
        series="jammy",
    )


async def test_given_charm_is_not_related_to_provider_when_deploy_then_status_is_blocked(
    ops_test: OpsTest,
):
    assert ops_test.model
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=1000)


async def test_given_provider_is_related_then_status_is_active(
    ops_test: OpsTest,
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:{RELATION_NAME_TO_TLS_PROVIDER}",
        relation2=TLS_PROVIDER_CHARM_NAME,
    )

    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)


async def test_given_tls_requirer1_is_deployed_and_related_then_certificate_is_created_and_passed_correctly(  # noqa: E501
    ops_test: OpsTest,
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:{RELATION_NAME_TO_TLS_REQUIRER}", relation2=TLS_REQUIRER1
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
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:{RELATION_NAME_TO_TLS_REQUIRER}",
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


async def test_given_tls_requirer1_has_first_csr_constraint_then_second_csr_rejected(
    ops_test: OpsTest,
):
    assert ops_test.model
    constraints_app = ops_test.model.applications[APPLICATION_NAME]
    assert isinstance(constraints_app, Application)
    await constraints_app.set_config({"limit-to-one-request": "True"})

    requirer1_app = ops_test.model.applications[TLS_REQUIRER1]
    assert isinstance(requirer1_app, Application)
    await requirer1_app.scale(2)
    await ops_test.model.wait_for_idle(
        apps=[TLS_REQUIRER1, APPLICATION_NAME], status="active", timeout=1000
    )

    action_output0 = await run_get_certificate_action(ops_test, TLS_REQUIRER1)
    assert action_output0["certificate"] is not None

    action_output1 = await run_get_certificate_action(ops_test, TLS_REQUIRER1, 1)
    assert action_output1.get("certificate") is None


async def test_given_limit_to_first_requester_enabled_and_requirer4_is_first_when_requirer5_requests_cert_then_csr_rejected(  # noqa E501
    ops_test: OpsTest,
):
    assert ops_test.model
    constraints_app = ops_test.model.applications[APPLICATION_NAME]
    assert isinstance(constraints_app, Application)
    await constraints_app.set_config({"limit-to-first-requester": "True"})

    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:{RELATION_NAME_TO_TLS_REQUIRER}",
        relation2=TLS_REQUIRER4,
    )
    await ops_test.model.wait_for_idle(
        apps=[TLS_REQUIRER4, APPLICATION_NAME], status="active", timeout=1000
    )

    action_output = await run_get_certificate_action(ops_test, TLS_REQUIRER4)
    assert action_output.get("certificate") is not None

    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:{RELATION_NAME_TO_TLS_REQUIRER}",
        relation2=TLS_REQUIRER5,
    )
    await ops_test.model.wait_for_idle(
        apps=[TLS_REQUIRER5, APPLICATION_NAME], status="active", timeout=1000
    )

    action_output = await run_get_certificate_action(ops_test, TLS_REQUIRER5)
    assert action_output.get("certificate") is None


async def test_given_subject_regex_is_configured_when_requirer3_requests_cert_then_csr_rejected(
    ops_test: OpsTest,
):
    assert ops_test.model
    constraints_app = ops_test.model.applications[APPLICATION_NAME]
    assert isinstance(constraints_app, Application)
    await constraints_app.set_config({"allowed-common-name": "thisdoesnotmatch.*"})

    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:{RELATION_NAME_TO_TLS_REQUIRER}",
        relation2=TLS_REQUIRER3,
    )
    await ops_test.model.wait_for_idle(
        apps=[TLS_REQUIRER3, APPLICATION_NAME], status="active", timeout=1000
    )

    action_output = await run_get_certificate_action(ops_test, TLS_REQUIRER3)
    assert action_output.get("certificate") is None


async def run_get_certificate_action(
    ops_test: OpsTest, app_name: str, unit_number: int = 0
) -> dict:
    """Run `get-certificate` on a unit of app_name.

    Args:
        ops_test (OpsTest): OpsTest
        app_name (str): Application Name to target
        unit_number (int): Unit number of the application

    Returns:
        dict: Action output
    """
    assert ops_test.model
    tls_requirer_unit = ops_test.model.units[f"{app_name}/{unit_number}"]
    assert tls_requirer_unit
    action = await tls_requirer_unit.run_action(
        action_name="get-certificate",
    )
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output
