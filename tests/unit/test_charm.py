# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import unittest
from unittest.mock import Mock

from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import-not-found]  # noqa: E501
    CertificateAvailableEvent,
    CertificateCreationRequestEvent,
    CertificateInvalidatedEvent,
    CertificateRevocationRequestEvent,
)
from ops import testing
from ops.model import ActiveStatus, BlockedStatus

from charm import TLSConstraintsCharm, logger

PROVIDES_RELATION_NAME = "certificates-provides"
REQUIRES_RELATION_NAME = "certificates-requires"


def get_json_csr_list(csr: str = "test_csr", is_ca: bool = False):
    return json.dumps(
        [
            {
                "certificate_signing_request": csr,
                "is_ca": is_ca,
            }
        ]
    )


class TestCharm(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = testing.Harness(TLSConstraintsCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(True)
        self.harness.begin()

    def test_given_not_related_to_provider_when_on_install_then_status_is_blocked(self) -> None:
        self.harness.charm.on.install.emit()
        self.assertEqual(
            BlockedStatus("Waiting for TLS certificates provider relation"),
            self.harness.charm.unit.status,
        )

    def test_given_installed_when_related_to_tls_provider_then_status_is_active(self) -> None:
        self._integrate_provider()

        self.assertEqual(
            ActiveStatus(),
            self.harness.charm.unit.status,
        )

    def test_given_provider_not_related_when_related_to_requirer_then_status_is_blocked(
        self,
    ) -> None:
        self._integrate_requirer()

        self.assertEqual(
            BlockedStatus("Waiting for TLS certificates provider relation"),
            self.harness.charm.unit.status,
        )

    def test_given_no_provider_related_when_requirer_requests_certificate_then_status_is_blocked(
        self,
    ) -> None:
        self._integrate_requirer()

        self.harness.charm._on_certificate_creation_request(event=Mock())

        self.assertEqual(
            BlockedStatus("Waiting for TLS certificates provider relation"),
            self.harness.charm.unit.status,
        )

    def test_given_no_provider_related_when_requirer_requests_certificate_then_event_is_defered(  # noqa: E501
        self,
    ) -> None:
        requirer_relation_id = self._integrate_requirer()

        event = CertificateCreationRequestEvent(
            handle=Mock(),
            certificate_signing_request="test_csr",
            relation_id=requirer_relation_id,
        )
        self.harness.charm._on_certificate_creation_request(event=event)

        self.assertTrue(event.deferred)

    def test_given_provider_related_when_requirer_requests_certificate_then_csr_is_forwarded_to_provider(  # noqa: E501
        self,
    ) -> None:
        self._integrate_provider()
        requirer_relation_id = self._integrate_requirer()

        event = CertificateCreationRequestEvent(
            handle=Mock(),
            certificate_signing_request="test_csr",
            relation_id=requirer_relation_id,
        )
        self.harness.charm._on_certificate_creation_request(event=event)

        requested_csrs = (
            self.harness.charm.certificates_provider.get_certificate_signing_requests()
        )
        self.assertEqual(len(requested_csrs), 1)
        self.assertEqual(requested_csrs[0]["certificate_signing_request"], "test_csr")
        self.assertFalse(requested_csrs[0]["ca"])

    def test_given_no_provider_related_when_requirer_requests_certificate_revocation_then_status_is_blocked(  # noqa: E501
        self,
    ) -> None:
        requirer_relation_id = self._integrate_requirer()
        event = CertificateCreationRequestEvent(
            handle=Mock(),
            certificate_signing_request="test_csr",
            relation_id=requirer_relation_id,
        )
        self.harness.charm._on_certificate_creation_request(event=event)
        self.harness.charm.unit.status = ActiveStatus()
        self.harness.charm._on_certificate_revocation_request(event=Mock())

        self.assertEqual(
            BlockedStatus("Waiting for TLS certificates provider relation"),
            self.harness.charm.unit.status,
        )

    def test_given_provider_related_when_requirer_requests_certificate_revocation_then_revocation_is_forwarded_to_provider(  # noqa: E501
        self,
    ) -> None:
        self._integrate_provider()
        requirer_relation_id = self._integrate_requirer()

        event = CertificateCreationRequestEvent(
            handle=Mock(),
            certificate_signing_request="test_csr",
            relation_id=requirer_relation_id,
        )
        self.harness.charm._on_certificate_creation_request(event=event)

        revoke_event = CertificateRevocationRequestEvent(
            handle=Mock(),
            certificate="cert",
            certificate_signing_request="test_csr",
            ca="ca",
            chain="chain",
        )
        self.harness.charm._on_certificate_revocation_request(event=revoke_event)
        requested_csrs = (
            self.harness.charm.certificates_provider.get_certificate_signing_requests()
        )
        self.assertEqual(len(requested_csrs), 0)

    def test_given_requirer_requested_certificate_when_certificate_available_then_certificate_is_forwarded_to_requirer(  # noqa: E501
        self,
    ) -> None:
        self._integrate_provider()
        requirer_relation_id = self._integrate_requirer()

        self.harness.update_relation_data(
            requirer_relation_id,
            "certificates-requirer/0",
            key_values={"certificate_signing_requests": get_json_csr_list()},
        )

        available_event = CertificateAvailableEvent(
            handle=Mock(),
            certificate_signing_request="test_csr",
            certificate="test_cert",
            ca="test_ca",
            chain=["test_ca", "test_intermediate"],
        )
        self.harness.charm._on_certificate_available(event=available_event)

        requirers_certificates = self.harness.charm.certificates_requirers.get_issued_certificates(
            requirer_relation_id
        )
        self.assertEqual(requirers_certificates["certificates-requirer"][0]["csr"], "test_csr")
        self.assertEqual(
            requirers_certificates["certificates-requirer"][0]["certificate"], "test_cert"
        )

    def test_given_no_requested_certificate_when_certificate_available_then_error_is_logged(
        self,
    ) -> None:
        self._integrate_provider()
        self._integrate_requirer()

        available_event = CertificateAvailableEvent(
            handle=Mock(),
            certificate_signing_request="test_csr",
            certificate="test_cert",
            ca="test_ca",
            chain=["test_ca", "test_intermediate"],
        )
        with self.assertLogs(logger, level="ERROR") as logs:
            self.harness.charm._on_certificate_available(event=available_event)

        self.assertIn("ERROR:charm:Could not find the relation for CSR: test_csr.", logs.output)

    def test_given_duplicate_requested_certificate_when_certificate_available_then_error_is_logged(
        self,
    ) -> None:
        self._integrate_provider()
        requirer1_relation_id = self._integrate_requirer()
        self.harness.update_relation_data(
            requirer1_relation_id,
            "certificates-requirer/0",
            key_values={"certificate_signing_requests": get_json_csr_list()},
        )
        requirer2_relation_id = self._integrate_requirer("certificates-requirer2")
        self.harness.update_relation_data(
            requirer2_relation_id,
            "certificates-requirer2/0",
            key_values={"certificate_signing_requests": get_json_csr_list()},
        )

        available_event = CertificateAvailableEvent(
            handle=Mock(),
            certificate_signing_request="test_csr",
            certificate="test_cert",
            ca="test_ca",
            chain=["test_ca", "test_intermediate"],
        )
        with self.assertLogs(logger, level="ERROR") as logs:
            self.harness.charm._on_certificate_available(event=available_event)

        self.assertIn(
            "ERROR:charm:Multiple requirers have the same CSR. Cannot choose one between relation IDs: {1, 2}",  # noqa: E501
            logs.output,
        )

    def test_given_provided_certificate_when_certificate_invalidated_then_invalidation_is_sent_to_requester(  # noqa: E501
        self,
    ) -> None:
        self._integrate_provider()
        requirer_relation_id = self._integrate_requirer()
        # TODO
        self.harness.update_relation_data(
            requirer_relation_id,
            "certificates-requirer/0",
            key_values={"certificate_signing_requests": get_json_csr_list()},
        )
        available_event = CertificateAvailableEvent(
            handle=Mock(),
            certificate_signing_request="test_csr",
            certificate="test_cert",
            ca="test_ca",
            chain=["test_ca", "test_intermediate"],
        )
        self.harness.charm._on_certificate_available(event=available_event)

        requirers_certificates = self.harness.charm.certificates_requirers.get_issued_certificates(
            requirer_relation_id
        )
        self.assertEqual(len(requirers_certificates["certificates-requirer"]), 1)

        invalidated_event = CertificateInvalidatedEvent(
            handle=Mock(),
            reason="revoked",
            certificate_signing_request="test_csr",
            certificate="test_cert",
            ca="test_ca",
            chain=["test_ca", "test_intermediate"],
        )
        self.harness.charm._on_certificate_invalidated(event=invalidated_event)

        requirers_certificates = self.harness.charm.certificates_requirers.get_issued_certificates(
            requirer_relation_id
        )
        self.assertEqual(len(requirers_certificates["certificates-requirer"]), 0)

    def test_given_provided_certificate_when_certificate_expired_then_event_is_ignored(
        self,
    ) -> None:
        self._integrate_provider()
        requirer_relation_id = self._integrate_requirer()
        self.harness.update_relation_data(
            requirer_relation_id,
            "certificates-requirer/0",
            key_values={"certificate_signing_requests": get_json_csr_list()},
        )
        available_event = CertificateAvailableEvent(
            handle=Mock(),
            certificate_signing_request="test_csr",
            certificate="test_cert",
            ca="test_ca",
            chain=["test_ca", "test_intermediate"],
        )
        self.harness.charm._on_certificate_available(event=available_event)

        requirers_certificates = self.harness.charm.certificates_requirers.get_issued_certificates(
            requirer_relation_id
        )
        self.assertEqual(len(requirers_certificates["certificates-requirer"]), 1)

        invalidated_event = CertificateInvalidatedEvent(
            handle=Mock(),
            reason="expired",
            certificate_signing_request="test_csr",
            certificate="test_cert",
            ca="test_ca",
            chain=["test_ca", "test_intermediate"],
        )
        self.harness.charm._on_certificate_invalidated(event=invalidated_event)

        requirers_certificates = self.harness.charm.certificates_requirers.get_issued_certificates(
            requirer_relation_id
        )
        self.assertEqual(len(requirers_certificates["certificates-requirer"]), 1)

    def test_given_multiple_provided_certificate_when_all_certificates_invalidated_then_all_certificates_are_removed(  # noqa: E501
        self,
    ) -> None:
        provider_relation_id = self._integrate_provider()
        requirer1_relation_id = self._integrate_requirer()
        self.harness.update_relation_data(
            requirer1_relation_id,
            "certificates-requirer/0",
            key_values={"certificate_signing_requests": get_json_csr_list("test_csr1")},
        )
        available_event = CertificateAvailableEvent(
            handle=Mock(),
            certificate_signing_request="test_csr1",
            certificate="test_cert1",
            ca="test_ca",
            chain=["test_ca", "test_intermediate"],
        )
        self.harness.charm._on_certificate_available(event=available_event)
        requirer2_relation_id = self._integrate_requirer("certificates-requirer2")
        self.harness.update_relation_data(
            requirer2_relation_id,
            "certificates-requirer2/0",
            key_values={"certificate_signing_requests": get_json_csr_list("test_csr2")},
        )
        available_event = CertificateAvailableEvent(
            handle=Mock(),
            certificate_signing_request="test_csr2",
            certificate="test_cert2",
            ca="test_ca",
            chain=["test_ca", "test_intermediate"],
        )
        self.harness.charm._on_certificate_available(event=available_event)

        requirers_certificates = (
            self.harness.charm.certificates_requirers.get_issued_certificates()
        )
        self.assertEqual(len(requirers_certificates), 2)

        self.harness.remove_relation(provider_relation_id)

        requirers_certificates = (
            self.harness.charm.certificates_requirers.get_issued_certificates()
        )
        for certificates in requirers_certificates.values():
            self.assertFalse(certificates)

    def _integrate_provider(self) -> int:
        provider_relation_id = self.harness.add_relation(
            relation_name=REQUIRES_RELATION_NAME,
            remote_app="certificates-provider",
        )
        self.harness.add_relation_unit(
            relation_id=provider_relation_id,
            remote_unit_name="certificates-provider/0",
        )
        return provider_relation_id

    def _integrate_requirer(
        self, app_name: str = "certificates-requirer", unit_id: int = 0
    ) -> int:
        requirer_relation_id = self.harness.add_relation(
            relation_name=PROVIDES_RELATION_NAME,
            remote_app=app_name,
        )
        self.harness.add_relation_unit(
            relation_id=requirer_relation_id,
            remote_unit_name=f"{app_name}/{unit_id}",
        )
        return requirer_relation_id
