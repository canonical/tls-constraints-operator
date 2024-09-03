# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import datetime
import json
from unittest.mock import Mock, patch

import pytest
from charm import AllowedFields, LimitToFirstRequester, LimitToOneRequest, TLSConstraintsCharm
from charms.tls_certificates_interface.v3.tls_certificates import (
    ProviderCertificate,
    RequirerCSR,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops import testing
from ops.model import ActiveStatus, BlockedStatus

TLS_LIB_PATH = "charms.tls_certificates_interface.v3.tls_certificates"

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
    patcher_tls_requires_request_certificate_creation = patch(
        f"{TLS_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    patcher_tls_requires_request_certificate_revocation = patch(
        f"{TLS_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_revocation"
    )
    patcher_tls_requires_get_assigned_certificates = patch(
        f"{TLS_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates"
    )
    patcher_tls_provides_get_outstanding_certificate_requests = patch(
        f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.get_outstanding_certificate_requests"
    )
    patcher_tls_provides_get_requirer_csrs = patch(
        f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.get_requirer_csrs"
    )

    patcher_tls_provides_get_certificates_for_which_no_csr_exists = patch(
        f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.get_certificates_for_which_no_csr_exists"
    )
    patcher_tls_provides_set_relation_certificate = patch(
        f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate"
    )
    patcher_tls_provides_remove_certificate = patch(
        f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.remove_certificate"
    )

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
        self.mock_tls_requires_request_certificate_creation = (
            self.patcher_tls_requires_request_certificate_creation.start()
        )
        self.mock_tls_requires_request_certificate_revocation = (
            self.patcher_tls_requires_request_certificate_revocation.start()
        )
        self.mock_tls_requires_get_assigned_certificates = (
            self.patcher_tls_requires_get_assigned_certificates.start()
        )
        self.mock_tls_provides_get_outstanding_certificate_requests = (
            self.patcher_tls_provides_get_outstanding_certificate_requests.start()
        )
        self.mock_tls_provides_get_requirer_csrs = (
            self.patcher_tls_provides_get_requirer_csrs.start()
        )
        self.mock_tls_provides_get_certificates_for_which_no_csr_exists = (
            self.patcher_tls_provides_get_certificates_for_which_no_csr_exists.start()
        )
        self.mock_tls_provides_set_relation_certificate = (
            self.patcher_tls_provides_set_relation_certificate.start()
        )
        self.mock_remove_certificate = self.patcher_tls_provides_remove_certificate.start()
        self.harness.begin()

    def test_given_not_related_to_provider_when_collect_unit_status_then_status_is_blocked(
        self,
    ) -> None:
        self.harness.evaluate_status()

        assert (
            BlockedStatus("Need a relation to a TLS certificates provider")
            == self.harness.charm.unit.status
        )

    def test_given_related_to_provider_when_collect_unit_status_then_status_is_active(
        self,
    ) -> None:
        self._integrate_provider()

        self.harness.evaluate_status()

        assert ActiveStatus() == self.harness.charm.unit.status

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
        self._integrate_provider()
        event = Mock()

        self.harness.charm._configure(event)

        self.mock_tls_requires_request_certificate_creation.assert_called_once_with(
            b"test_csr", False
        )

    def test_given_certificate_for_which_no_csr_exists_when_configure_then_revocation_is_forwarded_to_provider(  # noqa: E501
        self,
    ) -> None:
        self.mock_tls_provides_get_certificates_for_which_no_csr_exists.return_value = [
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
        self._integrate_provider()
        event = Mock()

        self.harness.charm._configure(event)

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
        self._integrate_provider()
        event = Mock()

        self.harness.charm._configure(event)

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
        self.harness.update_config({"limit-to-one-request": True})
        self._integrate_provider()
        event = Mock()

        self.harness.charm._configure(event)

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
        self._integrate_provider()
        event = Mock()

        self.harness.charm._configure(event)

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
        self._integrate_provider()
        event = Mock()

        self.harness.charm._configure(event)

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
        self._integrate_provider()
        event = Mock()

        self.harness.charm._configure(event)

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
        self._integrate_provider()
        event = Mock()

        self.harness.charm._configure(event)

        self.mock_remove_certificate.assert_not_called()

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

    def test_given_limit_to_one_filter_when_config_set_then_filter_available(
        self,
    ) -> None:
        self.harness.update_config({"limit-to-one-request": True})
        assert len(self.harness.charm._get_csr_filters()) > 0
        assert isinstance(self.harness.charm._get_csr_filters()[0], LimitToOneRequest)

    def test_given_limit_to_one_filter_when_given_one_csr_then_not_filtered(
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

    def test_given_limit_to_one_filter_when_given_two_csr_then_filtered(
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
