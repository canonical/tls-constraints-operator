# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from charms.tls_certificates_interface.v3.tls_certificates import (
    RequirerCSR,
)

from charm import LimitToOneRequest


class TestLimitToOneRequest:
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
