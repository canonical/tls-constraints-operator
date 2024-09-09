#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import datetime

import pytest
import scenario
from charms.tls_certificates_interface.v3.tls_certificates import (
    ProviderCertificate,
    RequirerCSR,
)

from charm import AllowedFields, LimitToFirstRequester, LimitToOneRequest
from tests.unit.fixtures import TLSConstraintsFixtures


class TestCharmConfigure(TLSConstraintsFixtures):
    def test_given_certificate_request_when_configure_then_csr_is_forwarded_to_provider(  # noqa: E501
        self,
    ) -> None:
        self.mock_tls_provides_get_outstanding_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=1,
                application_name="certificates-requirer",
                unit_name="certificates-requirer/0",
                csr="test_csr",
                is_ca=False,
            )
        ]
        tls_relation = scenario.Relation(
            endpoint="certificates-upstream",
            interface="tls-certificates",
        )

        state_in = scenario.State(
            relations={tls_relation},
            config={"limit-to-first-requester": False},
        )

        self.ctx.run(self.ctx.on.update_status(), state=state_in)

        self.mock_tls_requires_request_certificate_creation.assert_called_once_with(
            b"test_csr", False
        )

    def test_given_certificate_for_which_no_csr_exists_when_configure_then_revocation_is_forwarded_to_provider(  # noqa: E501
        self,
    ) -> None:
        self.mock_tls_provides_get_unsolicited_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                application_name="certificates-provider",
                csr="test_csr",
                certificate="test_cert",
                ca="test_ca",
                chain=["test_ca", "test_intermediate"],
                revoked=False,
                expiry_time=datetime.datetime.now(),
            )
        ]
        tls_relation = scenario.Relation(
            endpoint="certificates-upstream",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={tls_relation},
            config={"limit-to-first-requester": False},
        )

        self.ctx.run(self.ctx.on.update_status(), state=state_in)

        self.mock_tls_requires_request_certificate_revocation.assert_called_once_with(b"test_csr")

    def test_given_requirer_requested_certificate_when_configure_then_certificate_is_forwarded_to_requirer(  # noqa: E501
        self,
    ) -> None:
        self.mock_tls_requires_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                application_name="certificates-provider",
                csr="test_csr",
                certificate="test_cert",
                ca="test_ca",
                chain=["test_ca", "test_intermediate"],
                revoked=False,
                expiry_time=datetime.datetime.now(),
            ),
        ]
        self.mock_tls_provides_get_requirer_csrs.return_value = [
            RequirerCSR(
                relation_id=1,
                application_name="certificates-requirer",
                unit_name="certificates-requirer/0",
                csr="test_csr",
                is_ca=False,
            )
        ]
        tls_relation = scenario.Relation(
            endpoint="certificates-upstream",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={tls_relation},
            config={"limit-to-first-requester": False},
        )

        self.ctx.run(self.ctx.on.update_status(), state=state_in)

        self.mock_tls_provides_set_relation_certificate.assert_called_once_with(
            certificate="test_cert",
            certificate_signing_request="test_csr",
            ca="test_ca",
            chain=["test_ca", "test_intermediate"],
            relation_id=1,
        )

    def test_given_limit_to_one_request_set_when_second_certificate_requested_then_certificate_not_generated(  # noqa: E501
        self,
    ) -> None:
        self.mock_tls_provides_get_outstanding_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=1,
                application_name="certificates-requirer",
                unit_name="certificates-requirer/0",
                csr="test_csr",
                is_ca=False,
            )
        ]
        self.mock_tls_provides_get_requirer_csrs.return_value = [
            RequirerCSR(
                relation_id=1,
                application_name="certificates-requirer",
                unit_name="certificates-requirer/0",
                csr="test_csr",
                is_ca=False,
            ),
            RequirerCSR(
                relation_id=1,
                application_name="certificates-requirer",
                unit_name="certificates-requirer/1",
                csr="test_csr",
                is_ca=False,
            ),
        ]
        tls_relation = scenario.Relation(
            endpoint="certificates-upstream",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={tls_relation},
            config={
                "limit-to-first-requester": False,
                "limit-to-one-request": True,
            },
        )

        self.ctx.run(self.ctx.on.update_status(), state=state_in)

        self.mock_tls_requires_request_certificate_creation.assert_not_called()

    def test_given_no_requested_certificate_when_configure_then_error_is_logged(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        self.mock_tls_requires_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                application_name="certificates-provider",
                csr="test_csr",
                certificate="test_cert",
                ca="test_ca",
                chain=["test_ca", "test_intermediate"],
                revoked=False,
                expiry_time=datetime.datetime.now(),
            ),
        ]
        self.mock_tls_provides_get_requirer_csrs.return_value = []
        tls_relation = scenario.Relation(
            endpoint="certificates-upstream",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={tls_relation},
            config={"limit-to-first-requester": False},
        )

        self.ctx.run(self.ctx.on.update_status(), state=state_in)

        logs = [(record.levelname, record.module, record.message) for record in caplog.records]
        assert ("ERROR", "charm", "Could not find the relation for CSR: test_csr.") in logs

    def test_given_duplicate_requested_certificate_when_configure_then_error_is_logged(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        self.mock_tls_requires_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                application_name="certificates-provider",
                csr="same_csr",
                certificate="test_cert",
                ca="test_ca",
                chain=["test_ca", "test_intermediate"],
                revoked=False,
                expiry_time=datetime.datetime.now(),
            ),
        ]
        self.mock_tls_provides_get_requirer_csrs.return_value = [
            RequirerCSR(
                relation_id=2,
                application_name="certificates-requirer",
                unit_name="certificates-requirer/0",
                csr="same_csr",
                is_ca=False,
            ),
            RequirerCSR(
                relation_id=3,
                application_name="certificates-requirer",
                unit_name="certificates-requirer/0",
                csr="same_csr",
                is_ca=False,
            ),
        ]
        tls_relation = scenario.Relation(
            endpoint="certificates-upstream",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={tls_relation},
            config={"limit-to-first-requester": False},
        )

        self.ctx.run(self.ctx.on.update_status(), state=state_in)

        logs = [(record.levelname, record.module, record.message) for record in caplog.records]
        assert (
            "ERROR",
            "charm",
            "Multiple requirers have the same CSR. Cannot choose one between relation IDs: {2, 3}",
        ) in logs

    def test_given_revoked_certificate_when_configure_then_invalidation_is_sent_to_requester(  # noqa: E501
        self,
    ) -> None:
        self.mock_tls_requires_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                application_name="certificates-provider",
                csr="test_csr",
                certificate="test_cert",
                ca="test_ca",
                chain=["test_ca", "test_intermediate"],
                revoked=True,
                expiry_time=datetime.datetime.now() + datetime.timedelta(days=1),
            ),
        ]
        self.mock_tls_provides_get_requirer_csrs.return_value = [
            RequirerCSR(
                relation_id=2,
                application_name="certificates-requirer",
                unit_name="certificates-requirer/0",
                csr="test_csr",
                is_ca=False,
            )
        ]
        tls_relation = scenario.Relation(
            endpoint="certificates-upstream",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={tls_relation},
            config={"limit-to-first-requester": False},
        )

        self.ctx.run(self.ctx.on.update_status(), state=state_in)

        self.mock_remove_certificate.assert_called_once_with(certificate="test_cert")

    def test_given_certificate_not_revoked_when_configure_then_certificate_not_removed(
        self,
    ) -> None:
        self.mock_tls_requires_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                application_name="certificates-provider",
                csr="test_csr",
                certificate="test_cert",
                ca="test_ca",
                chain=["test_ca", "test_intermediate"],
                revoked=False,
                expiry_time=datetime.datetime.now(),
            ),
        ]
        self.mock_tls_provides_get_requirer_csrs.return_value = [
            RequirerCSR(
                relation_id=2,
                application_name="certificates-requirer",
                unit_name="certificates-requirer/0",
                csr="test_csr",
                is_ca=False,
            )
        ]
        tls_relation = scenario.Relation(
            endpoint="certificates-upstream",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={tls_relation},
            config={"limit-to-first-requester": False},
        )

        self.ctx.run(self.ctx.on.update_status(), state=state_in)

        self.mock_remove_certificate.assert_not_called()

    def test_given_limit_to_one_filter_when_configure_then_filter_available(
        self,
    ) -> None:
        tls_relation = scenario.Relation(
            endpoint="certificates-upstream",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={tls_relation},
            config={"limit-to-first-requester": False, "limit-to-one-request": True},
        )

        with self.ctx(self.ctx.on.update_status(), state_in) as manager:
            assert len(manager.charm._get_csr_filters()) > 0  # type: ignore[reportAttributeAccessIssue]
            assert isinstance(manager.charm._get_csr_filters()[0], LimitToOneRequest)  # type: ignore[reportAttributeAccessIssue]

    def test_given_limit_to_first_requirer_filter_when_configure_then_filter_available(  # noqa: E501
        self,
    ) -> None:
        tls_relation = scenario.Relation(
            endpoint="certificates-upstream",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={tls_relation},
            config={"limit-to-first-requester": True},
        )
        with self.ctx(self.ctx.on.update_status(), state_in) as manager:
            assert len(manager.charm._get_csr_filters()) > 0  # type: ignore[reportAttributeAccessIssue]
            assert isinstance(manager.charm._get_csr_filters()[0], LimitToFirstRequester)  # type: ignore[reportAttributeAccessIssue]

    def test_given_allowlist_config_filter_when_config_set_then_filter_available(  # noqa: E501
        self,
    ) -> None:
        tls_relation = scenario.Relation(
            endpoint="certificates-upstream",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={tls_relation},
            config={
                "limit-to-first-requester": False,
                "allowed-dns": r"myapp-([0-9]+)?\.mycompany\.com",
                "allowed-ips": r"172\.25\.0\.[0-9]*",
                "allowed-oids": r"1\.3\.6\.1\.4\.1\.28978\.[0-9.]*",
                "allowed-common-name": r"myapp-([0-9]+)?\.mycompany\.com",
                "allowed-organization": r"Canonical Ltd\.",
                "allowed-email": r".*@canonical\.com",
                "allowed-country-code": "(UK|CA|PL|AE|HU|FR|TR|IT)$",
            },
        )
        with self.ctx(self.ctx.on.update_status(), state_in) as manager:
            assert len(manager.charm._get_csr_filters()) > 0  # type: ignore[reportAttributeAccessIssue]
            assert isinstance(manager.charm._get_csr_filters()[0], AllowedFields)  # type: ignore[reportAttributeAccessIssue]
