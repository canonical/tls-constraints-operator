# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import itertools
import json
from unittest.mock import Mock

import pytest
from charm import AllowedFields, LimitToFirstRequester, LimitToOneRequest, TLSConstraintsCharm
from charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateAvailableEvent,
    CertificateCreationRequestEvent,
    CertificateInvalidatedEvent,
    CertificateRevocationRequestEvent,
    RequirerCSR,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops import testing
from ops.model import ActiveStatus, BlockedStatus

RELATION_NAME_TO_TLS_REQUIRER = "certificates-downstream"
RELATION_NAME_TO_TLS_PROVIDER = "certificates-upstream"


def get_json_csr_list(csr: str = "test_csr", is_ca: bool = False):
    return json.dumps(
        [
            {
                "certificate_signing_request": csr,
                "is_ca": is_ca,
            }
        ]
    )


class TestCharm:
    @pytest.fixture(scope="function", autouse=True)
    def setUp(self):
        self.harness = testing.Harness(TLSConstraintsCharm)
        self.harness.set_leader(True)
        self.harness.update_config({"limit-to-first-requester": False})
        self.client_key = generate_private_key()
        self.csr = generate_csr(private_key=self.client_key, subject="test_subject")
        self.ca_key = generate_private_key()
        self.ca_certificate = generate_ca(
            private_key=self.ca_key,
            subject="test_ca",
        )
        self.certificate = generate_certificate(
            csr=self.csr,
            ca=self.ca_certificate,
            ca_key=self.ca_key,
        )
        self.harness.begin()

    def test_given_not_related_to_provider_when_on_install_then_status_is_blocked(
        self,
    ) -> None:
        self.harness.charm.on.install.emit()
        assert (
            BlockedStatus("Need a relation to a TLS certificates provider")
            == self.harness.charm.unit.status
        )

    def test_given_installed_when_related_to_tls_provider_then_status_is_active(
        self,
    ) -> None:
        self._integrate_provider()

        assert ActiveStatus() == self.harness.charm.unit.status

    def test_given_provider_not_related_when_related_to_requirer_then_status_is_blocked(
        self,
    ) -> None:
        self._integrate_requirer()

        assert (
            BlockedStatus("Need a relation to a TLS certificates provider")
            == self.harness.charm.unit.status
        )

    def test_given_no_provider_related_when_requirer_requests_certificate_then_status_is_blocked(
        self,
    ) -> None:
        self._integrate_requirer()

        self.harness.charm._on_certificate_creation_request(event=Mock())

        assert (
            BlockedStatus("Need a relation to a TLS certificates provider")
            == self.harness.charm.unit.status
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

        assert event.deferred

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
        assert len(requested_csrs) == 1
        assert requested_csrs[0].csr == "test_csr"
        assert not requested_csrs[0].is_ca

    def test_given_no_provider_related_and_active_status_when_requirer_requests_certificate_revocation_then_status_is_blocked(  # noqa: E501
        self,
    ) -> None:
        self.harness.charm.unit.status = ActiveStatus()

        self.harness.charm._on_certificate_revocation_request(event=Mock())

        assert (
            BlockedStatus("Need a relation to a TLS certificates provider")
            == self.harness.charm.unit.status
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
        assert len(requested_csrs) == 0

    def test_given_requirer_requested_certificate_when_certificate_available_then_certificate_is_forwarded_to_requirer(  # noqa: E501
        self,
    ) -> None:
        self._integrate_provider()
        requirer_relation_id = self._integrate_requirer()
        self.harness.update_relation_data(
            requirer_relation_id,
            "certificates-requirer/0",
            key_values={
                "certificate_signing_requests": get_json_csr_list(csr=self.csr.decode().strip())
            },
        )
        available_event = CertificateAvailableEvent(
            handle=Mock(),
            certificate_signing_request=self.csr.decode().strip(),
            certificate=self.certificate.decode().strip(),
            ca=self.ca_certificate.decode().strip(),
            chain=[self.ca_certificate.decode().strip()],
        )
        self.harness.charm._on_certificate_available(event=available_event)

        requirers_certificates = self.harness.charm.certificates_requirers.get_issued_certificates(
            requirer_relation_id
        )
        assert requirers_certificates[0].csr.strip() == self.csr.decode().strip()
        assert requirers_certificates[0].certificate.strip() == self.certificate.decode().strip()

    def test_given_limit_to_one_request_set_when_second_certificate_requested_then_certificate_not_generated(  # noqa: E501
        self,
    ) -> None:
        self.harness.update_config({"limit-to-one-request": True})

        self._integrate_provider()
        appname = "certificates-requirer"
        requirer_relation_id = self._integrate_requirer(appname, 0)
        self.harness.add_relation_unit(
            relation_id=requirer_relation_id,
            remote_unit_name=f"{appname}/{1}",
        )
        self.harness.update_relation_data(
            requirer_relation_id,
            "certificates-requirer/0",
            key_values={"certificate_signing_requests": get_json_csr_list()},
        )
        self.harness.update_relation_data(
            requirer_relation_id,
            "certificates-requirer/1",
            key_values={"certificate_signing_requests": get_json_csr_list(csr="test_csr2")},
        )
        databags = list(
            itertools.chain(
                *[
                    json.loads(
                        self.harness.get_relation_data(requirer_relation_id, f"{appname}/{i}").get(
                            "certificate_signing_requests", ""
                        )
                    )
                    for i in range(2)
                ]
            )
        )
        certificates_passed_along = (
            self.harness.charm.certificates_provider.get_certificate_signing_requests()
        )

        assert len(databags) == 2
        assert len(certificates_passed_along) == 1

    def test_given_no_requested_certificate_when_certificate_available_then_error_is_logged(
        self, caplog: pytest.LogCaptureFixture
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
        self.harness.charm._on_certificate_available(event=available_event)

        logs = [(record.levelname, record.module, record.message) for record in caplog.records]
        assert ("ERROR", "charm", "Could not find the relation for CSR: test_csr.") in logs

    def test_given_duplicate_requested_certificate_when_certificate_available_then_error_is_logged(
        self, caplog: pytest.LogCaptureFixture
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
        self.harness.charm._on_certificate_available(event=available_event)

        logs = [(record.levelname, record.module, record.message) for record in caplog.records]
        assert (
            "ERROR",
            "charm",
            "Multiple requirers have the same CSR. Cannot choose one between relation IDs: {1, 2}",
        ) in logs

    def test_given_provided_certificate_when_certificate_invalidated_then_invalidation_is_sent_to_requester(  # noqa: E501
        self,
    ) -> None:
        self._integrate_provider()
        requirer_relation_id = self._integrate_requirer()
        self.harness.update_relation_data(
            requirer_relation_id,
            "certificates-requirer/0",
            key_values={
                "certificate_signing_requests": get_json_csr_list(csr=self.csr.decode().strip())
            },
        )
        available_event = CertificateAvailableEvent(
            handle=Mock(),
            certificate_signing_request=self.csr.decode().strip(),
            certificate=self.certificate.decode().strip(),
            ca=self.ca_certificate.decode().strip(),
            chain=[self.ca_certificate.decode().strip()],
        )
        self.harness.charm._on_certificate_available(event=available_event)

        requirers_certificates = self.harness.charm.certificates_requirers.get_issued_certificates(
            requirer_relation_id
        )
        assert len(requirers_certificates) == 1

        invalidated_event = CertificateInvalidatedEvent(
            handle=Mock(),
            reason="revoked",
            certificate_signing_request=self.csr.decode().strip(),
            certificate=self.certificate.decode().strip(),
            ca=self.ca_certificate.decode().strip(),
            chain=[self.ca_certificate.decode().strip()],
        )
        self.harness.charm._on_certificate_invalidated(event=invalidated_event)

        requirers_certificates = self.harness.charm.certificates_requirers.get_issued_certificates(
            requirer_relation_id
        )
        assert len(requirers_certificates) == 0

    def test_given_provided_certificate_when_certificate_expired_then_event_is_ignored(
        self,
    ) -> None:
        self._integrate_provider()
        requirer_relation_id = self._integrate_requirer()
        self.harness.update_relation_data(
            requirer_relation_id,
            "certificates-requirer/0",
            key_values={
                "certificate_signing_requests": get_json_csr_list(csr=self.csr.decode().strip())
            },
        )
        available_event = CertificateAvailableEvent(
            handle=Mock(),
            certificate_signing_request=self.csr.decode().strip(),
            certificate=self.certificate.decode().strip(),
            ca=self.ca_certificate.decode().strip(),
            chain=[self.ca_certificate.decode().strip()],
        )
        self.harness.charm._on_certificate_available(event=available_event)

        requirers_certificates = self.harness.charm.certificates_requirers.get_issued_certificates(
            requirer_relation_id
        )
        assert len(requirers_certificates) == 1

        invalidated_event = CertificateInvalidatedEvent(
            handle=Mock(),
            reason="expired",
            certificate_signing_request=self.csr.decode().strip(),
            certificate=self.certificate.decode().strip(),
            ca=self.ca_certificate.decode().strip(),
            chain=[self.ca_certificate.decode().strip()],
        )
        self.harness.charm._on_certificate_invalidated(event=invalidated_event)

        requirers_certificates = self.harness.charm.certificates_requirers.get_issued_certificates(
            requirer_relation_id
        )
        assert len(requirers_certificates) == 1

    def test_given_multiple_provided_certificate_when_all_certificates_invalidated_then_all_certificates_are_removed(  # noqa: E501
        self,
    ) -> None:
        provider_relation_id = self._integrate_provider()
        requirer1_relation_id = self._integrate_requirer()
        self.harness.update_relation_data(
            requirer1_relation_id,
            "certificates-requirer/0",
            key_values={
                "certificate_signing_requests": get_json_csr_list(csr=self.csr.decode().strip())
            },
        )
        available_event = CertificateAvailableEvent(
            handle=Mock(),
            certificate_signing_request=self.csr.decode().strip(),
            certificate=self.certificate.decode().strip(),
            ca=self.ca_certificate.decode().strip(),
            chain=[self.ca_certificate.decode().strip()],
        )
        self.harness.charm._on_certificate_available(event=available_event)
        requirer2_relation_id = self._integrate_requirer("certificates-requirer2")
        new_csr = generate_csr(private_key=self.client_key, subject="test_subject2")
        new_certificate = generate_certificate(
            csr=new_csr,
            ca=self.ca_certificate,
            ca_key=self.ca_key,
        )
        self.harness.update_relation_data(
            requirer2_relation_id,
            "certificates-requirer2/0",
            key_values={
                "certificate_signing_requests": get_json_csr_list(csr=new_csr.decode().strip())
            },
        )
        available_event = CertificateAvailableEvent(
            handle=Mock(),
            certificate_signing_request=new_csr.decode().strip(),
            certificate=new_certificate.decode().strip(),
            ca=self.ca_certificate.decode().strip(),
            chain=[self.ca_certificate.decode().strip()],
        )
        self.harness.charm._on_certificate_available(event=available_event)

        requirers_certificates = (
            self.harness.charm.certificates_requirers.get_issued_certificates()
        )
        assert len(requirers_certificates) == 2

        self.harness.remove_relation(provider_relation_id)

        requirers_certificates = (
            self.harness.charm.certificates_requirers.get_issued_certificates()
        )
        assert len(requirers_certificates) == 0

    def _integrate_provider(self) -> int:
        provider_relation_id = self.harness.add_relation(
            relation_name=RELATION_NAME_TO_TLS_PROVIDER,
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
            relation_name=RELATION_NAME_TO_TLS_REQUIRER,
            remote_app=app_name,
        )
        self.harness.add_relation_unit(
            relation_id=requirer_relation_id,
            remote_unit_name=f"{app_name}/{unit_id}",
        )
        return requirer_relation_id

    def test_given_limit_to_one_filter_when_config_set_then_filter_available(  # noqa: E501
        self,
    ) -> None:
        self.harness.update_config({"limit-to-one-request": True})
        assert len(self.harness.charm._get_csr_filters()) > 0
        assert isinstance(self.harness.charm._get_csr_filters()[0], LimitToOneRequest)

    def test_given_limit_to_one_filter_when_given_one_csr_then_not_filtered(  # noqa: E501
        self,
    ) -> None:
        requirer_csrs = [
            RequirerCSR(
                relation_id=2,
                application_name="certificates-requirer",
                unit_name="certificates-requirer/0",
                csr="test_csr",
                is_ca=False,
            ),
            RequirerCSR(
                relation_id=3,
                application_name="certificates-requirer",
                unit_name="certificates-requirer/1",
                csr="test_csr2",
                is_ca=False,
            ),
        ]
        filter = LimitToOneRequest()
        assert filter.evaluate(b"", 1, requirer_csrs) is True

    def test_given_limit_to_one_filter_when_given_two_csr_then_filtered(  # noqa: E501
        self,
    ) -> None:
        requirer_csrs = [
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
                csr="test_csr2",
                is_ca=False,
            ),
        ]
        filter = LimitToOneRequest()
        assert filter.evaluate(b"", 1, requirer_csrs) is False

    def test_given_limit_to_first_requirer_filter_when_config_set_then_filter_available(  # noqa: E501
        self,
    ) -> None:
        self._integrate_provider()
        self.harness.update_config({"limit-to-first-requester": True})
        assert len(self.harness.charm._get_csr_filters()) > 0
        assert isinstance(self.harness.charm._get_csr_filters()[0], LimitToFirstRequester)

    def test_given_allowlist_config_filter_when_config_set_then_filter_available(  # noqa: E501
        self,
    ) -> None:
        self.harness.update_config(
            {
                "allowed-dns": r"myapp-([0-9]+)?\.mycompany\.com",
                "allowed-ips": r"172\.25\.0\.[0-9]*",
                "allowed-oids": r"1\.3\.6\.1\.4\.1\.28978\.[0-9.]*",
                "allowed-common-name": r"myapp-([0-9]+)?\.mycompany\.com",
                "allowed-organization": r"Canonical Ltd\.",
                "allowed-email": r".*@canonical\.com",
                "allowed-country-code": "(UK|CA|PL|AE|HU|FR|TR|IT)$",
            }
        )
        assert len(self.harness.charm._get_csr_filters()) > 0
        assert isinstance(self.harness.charm._get_csr_filters()[0], AllowedFields)

    def test_given_allowlist_config_filter_when_given_correct_csr_then_filter_passed(self):
        csr_options = {
            "subject": "myapp-1.mycompany.com",
            "sans_dns": ["myapp-1.mycompany.com"],
            "sans_ip": ["172.25.0.1"],
            "sans_oid": ["1.3.6.1.4.1.28978.3"],
            "organization": "Canonical Ltd.",
            "email_address": "me@canonical.com",
            "country_name": "US",
            "private_key": generate_private_key(),
        }
        rules = {
            "allowed-dns": r"myapp-([0-9]+)?\.mycompany\.com",
            "allowed-ips": r"172\.25\.0\.[0-9]*",
            "allowed-oids": r"1\.3\.6\.1\.4\.1\.28978\.[0-9.]*",
            "allowed-common-name": r"myapp-([0-9]+)?\.mycompany\.com",
            "allowed-organization": r"Canonical Ltd\.",
            "allowed-email": r".*@canonical\.com",
            "allowed-country-code": r"(UK|US|CA|PL|AE|HU|FR|TR|IT)$",
        }

        filter = AllowedFields(rules)
        valid_csr = generate_csr(**csr_options)
        assert filter.evaluate(valid_csr, 1, []) is True

    @pytest.mark.parametrize(
        "invalid_field,expected_log_message",
        [
            (
                {"subject": "notmyapp.mycompany.com"},
                "error with common name: field validation failed",
            ),
            (
                {"sans_dns": ["notmyapp.mycompany.com"]},
                "error with dns in san: field validation failed",
            ),
            (
                {"sans_ip": ["127.0.0.1"]},
                "error with ip in san: field validation failed",
            ),
            (
                {"sans_oid": ["1.3.6.1.4.1.2897.3"]},
                "error with oid in san: field validation failed",
            ),
            (
                {"organization": "Canonical Inc."},
                "error with organization: field validation failed",
            ),
            (
                {"email_address": "me@notcanonical.com"},
                "error with email address: field validation failed",
            ),
            (
                {"country_name": "TG"},
                "error with country code: field validation failed",
            ),
        ],
    )
    def test_given_allowlist_config_filter_when_invalid_csr_given_then_csr_filtered(
        self, caplog: pytest.LogCaptureFixture, invalid_field, expected_log_message
    ) -> None:
        rules = {
            "allowed-dns": r"myapp-([0-9]+)?\.mycompany\.com",
            "allowed-ips": r"172\.25\.0\.[0-9]*",
            "allowed-oids": r"1\.3\.6\.1\.4\.1\.28978\.[0-9.]*",
            "allowed-common-name": r"myapp-([0-9]+)?\.mycompany\.com",
            "allowed-organization": r"Canonical Ltd\.",
            "allowed-email": r".*@canonical\.com",
            "allowed-country-code": r"(UK|US|CA|PL|AE|HU|FR|TR|IT)$",
        }
        csr_options = {
            "subject": "myapp-1.mycompany.com",
            "sans_dns": ["myapp-1.mycompany.com"],
            "sans_ip": ["172.25.0.1"],
            "sans_oid": ["1.3.6.1.4.1.28978.3"],
            "organization": "Canonical Ltd.",
            "email_address": "me@canonical.com",
            "country_name": "US",
            "private_key": generate_private_key(),
        }
        filter = AllowedFields(rules)
        csr_options.update(invalid_field)
        invalid_csr = generate_csr(**csr_options)

        assert filter.evaluate(invalid_csr, 1, []) is False
        logs = [(record.levelname, record.module, record.message) for record in caplog.records]
        assert ("WARNING", "charm", expected_log_message) in logs
