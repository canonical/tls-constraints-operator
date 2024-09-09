#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import patch

import pytest
import scenario

from charm import TLSConstraintsCharm

TLS_LIB_PATH = "charms.tls_certificates_interface.v3.tls_certificates"


class TLSConstraintsFixtures:
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
    patcher_tls_provides_get_unsolicited_certificates = patch(
        f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.get_unsolicited_certificates"
    )
    patcher_tls_provides_set_relation_certificate = patch(
        f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate"
    )
    patcher_tls_provides_remove_certificate = patch(
        f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.remove_certificate"
    )

    @pytest.fixture(autouse=True)
    def setUp(self, request):
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
        self.mock_tls_provides_get_unsolicited_certificates = (
            self.patcher_tls_provides_get_unsolicited_certificates.start()
        )
        self.mock_tls_provides_set_relation_certificate = (
            self.patcher_tls_provides_set_relation_certificate.start()
        )
        self.mock_remove_certificate = self.patcher_tls_provides_remove_certificate.start()

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=TLSConstraintsCharm,
        )
