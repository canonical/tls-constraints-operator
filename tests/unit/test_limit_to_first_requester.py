# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
from random import choice

import pytest
from charm import LimitToFirstRequester
from charms.tls_certificates_interface.v3.tls_certificates import (
    generate_csr,
    generate_private_key,
)

MY_RELATION_ID = 1
OTHER_RELATION_ID = 2

REQUESTED_SUBJECT = "Test Subject"
REQUESTED_DNS = ["test-0.example.com", "test-internal.example.com"]
REQUESTED_IPS = ["2.2.2.2", "10.142.42.2"]
REQUESTED_OIDS = ["1.2.3.4.42.120", "1.2.3.3.42.121"]

PRIVATE_KEY = generate_private_key()
CSR = generate_csr(
    private_key=PRIVATE_KEY,
    subject=REQUESTED_SUBJECT,
    sans_dns=REQUESTED_DNS,
    sans_ip=REQUESTED_IPS,
    sans_oid=REQUESTED_OIDS,
    organization="Example inc.",
    email_address="admin@example.com",
    country_name="CA",
)


class TestLimitToFirstRequester:

    @pytest.mark.parametrize(
        "dns,ip,oid,expected",
        [
            pytest.param({}, {}, {}, True, id="no_previous_requesters"),
            pytest.param(
                {
                    "pizza.example.com": OTHER_RELATION_ID,
                    "poulah.example.com": OTHER_RELATION_ID,
                },
                {
                    "1.1.1.1": OTHER_RELATION_ID,
                    "192.168.0.1": OTHER_RELATION_ID,
                },
                {
                    "1.2.3.4.42.500": OTHER_RELATION_ID,
                    "1.2.3.4.42.120.55": OTHER_RELATION_ID,
                },
                True,
                id="previous_requesters_do_not_match"
            ),
            pytest.param(
                {REQUESTED_SUBJECT: OTHER_RELATION_ID},
                {},
                {},
                False,
                id="dns_subject_previously_requested",
            ),
            pytest.param(
                {REQUESTED_SUBJECT: MY_RELATION_ID}, {}, {},
                True,
                id="dns_subject_previously_requested_by_us",
            ),
            pytest.param(
                {choice(REQUESTED_DNS): OTHER_RELATION_ID}, {}, {},
                False,
                id="dns_san_previously_requested",
            ),
            pytest.param(
                {choice(REQUESTED_DNS): MY_RELATION_ID}, {}, {},
                True,
                id="ip_san_previously_requested_by_us",
            ),
            pytest.param(
                {}, {REQUESTED_SUBJECT: OTHER_RELATION_ID}, {},
                False,
                id="ip_subject_previously_requested",
            ),
            pytest.param(
                {}, {REQUESTED_SUBJECT: MY_RELATION_ID}, {},
                True,
                id="ip_subject_previously_requested_by_us",
            ),
            pytest.param(
                {}, {choice(REQUESTED_IPS): OTHER_RELATION_ID}, {},
                False,
                id="ip_san_previously_requested",
            ),
            pytest.param(
                {}, {choice(REQUESTED_IPS): MY_RELATION_ID}, {},
                True,
                id="ip_san_previously_requested_by_us",
            ),
            pytest.param(
                {}, {}, {REQUESTED_SUBJECT: OTHER_RELATION_ID},
                False,
                id="oid_subject_previously_requested",
            ),
            pytest.param(
                {}, {}, {REQUESTED_SUBJECT: MY_RELATION_ID},
                True,
                id="oid_subject_previously_requested_by_us",
            ),
            pytest.param(
                {}, {}, {choice(REQUESTED_OIDS): OTHER_RELATION_ID},
                False,
                id="oid_san_previously_requested",
            ),
            pytest.param(
                {}, {}, {choice(REQUESTED_OIDS): MY_RELATION_ID},
                True,
                id="oid_san_previously_requested_by_us",
            ),
        ],
    )
    def test_given_previous_requesters_when_evaluate_csr_then_csr_is_allowed_or_denied(
        self, dns, ip, oid, expected
    ):
        filter = LimitToFirstRequester(registered_dns=dns, registered_ips=ip, registered_oids=oid)
        assert filter.evaluate(CSR, MY_RELATION_ID, []) is expected

    @pytest.mark.parametrize(
        "dns,ip,oid,expected",
        [
            pytest.param(
                {REQUESTED_SUBJECT: OTHER_RELATION_ID}, {}, {},
                f"CSR denied for relation ID {MY_RELATION_ID}, "
                + f"DNS '{REQUESTED_SUBJECT}' already requested.",
                id="dns_san_previously_requested",
            ),
            pytest.param(
                {}, {REQUESTED_SUBJECT: OTHER_RELATION_ID}, {},
                f"CSR denied for relation ID {MY_RELATION_ID}, "
                + f"IP '{REQUESTED_SUBJECT}' already requested.",
                id="ip_subject_previously_requested",
            ),
            pytest.param(
                {}, {}, {REQUESTED_SUBJECT: OTHER_RELATION_ID},
                f"CSR denied for relation ID {MY_RELATION_ID}, "
                + f"OID '{REQUESTED_SUBJECT}' already requested.",
                id="oid_san_previously_requested",
            ),
        ],
    )
    def test_given_previous_requesters_when_evaluate_csr_then_denials_are_logged(
        self, dns, ip, oid, expected, caplog
    ):
        filter = LimitToFirstRequester(registered_dns=dns, registered_ips=ip, registered_oids=oid)
        filter.evaluate(CSR, MY_RELATION_ID, [])
        logs = [(record.levelname, record.module, record.message) for record in caplog.records]
        assert ("WARNING", "charm", expected) in logs

    def test_given_previous_requesters_when_evaluate_csr_then_approvals_are_not_logged(
        self, caplog
    ):
        filter = LimitToFirstRequester(registered_dns={}, registered_ips={}, registered_oids={})
        filter.evaluate(CSR, MY_RELATION_ID, [])
        logs = [(record.levelname, record.module, record.message) for record in caplog.records]
        assert len(logs) == 0

    def test_given_csr_without_sans_extension_when_evaluate_then_does_not_crash(self):
        csr = generate_csr(
            private_key=PRIVATE_KEY,
            subject=REQUESTED_SUBJECT,
            organization="Example inc.",
            email_address="admin@example.com",
            country_name="CA",
        )
        filter = LimitToFirstRequester(registered_dns={}, registered_ips={}, registered_oids={})
        assert filter.evaluate(csr, MY_RELATION_ID, []) is True
