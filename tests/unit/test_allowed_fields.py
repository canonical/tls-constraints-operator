# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from charms.tls_certificates_interface.v3.tls_certificates import (
    generate_csr,
    generate_private_key,
)

from charm import AllowedFields


class TestAllowedFields:
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
