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
        "requested_identifiers,expected",
        [
            pytest.param({}, True, id="no_previous_requesters"),
            pytest.param({"dns": {}, "ip": {}, "oid": {}}, True, id="empty_previous_requesters"),
            pytest.param(
                {
                    "dns": {
                        "pizza.example.com": OTHER_RELATION_ID,
                        "poulah.example.com": OTHER_RELATION_ID,
                    },
                    "ip": {
                        "1.1.1.1": OTHER_RELATION_ID,
                        "192.168.0.1": OTHER_RELATION_ID,
                    },
                    "oid": {
                        "1.2.3.4.42.500": OTHER_RELATION_ID,
                        "1.2.3.4.42.120.55": OTHER_RELATION_ID,
                    }
                },
                True,
                id="previous_requesters_do_not_match"
            ),
            pytest.param(
                {
                    "dns": {REQUESTED_SUBJECT: OTHER_RELATION_ID},
                    "ip": {},
                    "oid": {}
                },
                False,
                id="dns_subject_previously_requested",
            ),
            pytest.param(
                {"dns": {REQUESTED_SUBJECT: MY_RELATION_ID}, "ip": {}, "oid": {}},
                True,
                id="dns_subject_previously_requested_by_us",
            ),
            pytest.param(
                {"dns": {choice(REQUESTED_DNS): OTHER_RELATION_ID}, "ip": {}, "oid": {}},
                False,
                id="dns_san_previously_requested",
            ),
            pytest.param(
                {"dns": {choice(REQUESTED_DNS): MY_RELATION_ID}, "ip": {}, "oid": {}},
                True,
                id="ip_san_previously_requested_by_us",
            ),
            pytest.param(
                {"dns": {}, "ip": {REQUESTED_SUBJECT: OTHER_RELATION_ID}, "oid": {}},
                False,
                id="ip_subject_previously_requested",
            ),
            pytest.param(
                {"dns": {}, "ip": {REQUESTED_SUBJECT: MY_RELATION_ID}, "oid": {}},
                True,
                id="ip_subject_previously_requested_by_us",
            ),
            pytest.param(
                {"dns": {}, "ip": {choice(REQUESTED_IPS): OTHER_RELATION_ID}, "oid": {}},
                False,
                id="ip_san_previously_requested",
            ),
            pytest.param(
                {"dns": {}, "ip": {choice(REQUESTED_IPS): MY_RELATION_ID}, "oid": {}},
                True,
                id="ip_san_previously_requested_by_us",
            ),
            pytest.param(
                {"dns": {}, "ip": {}, "oid": {REQUESTED_SUBJECT: OTHER_RELATION_ID}},
                False,
                id="oid_subject_previously_requested",
            ),
            pytest.param(
                {"dns": {}, "ip": {}, "oid": {REQUESTED_SUBJECT: MY_RELATION_ID}},
                True,
                id="oid_subject_previously_requested_by_us",
            ),
            pytest.param(
                {"dns": {}, "ip": {}, "oid": {choice(REQUESTED_OIDS): OTHER_RELATION_ID}},
                False,
                id="oid_san_previously_requested",
            ),
            pytest.param(
                {"dns": {}, "ip": {}, "oid": {choice(REQUESTED_OIDS): MY_RELATION_ID}},
                True,
                id="oid_san_previously_requested_by_us",
            ),
        ],
    )
    def test_given_previous_requesters_when_evaluate_csr_then_csr_is_allowed_or_denied(
        self,
        requested_identifiers,
        expected
    ):
        filter = LimitToFirstRequester(requested_identifiers)
        assert filter.evaluate(CSR, MY_RELATION_ID, []) is expected

    @pytest.mark.parametrize(
        "requested_identifiers,expected",
        [
            pytest.param(
                {"dns": {REQUESTED_SUBJECT: OTHER_RELATION_ID}, "ip": {}, "oid": {}},
                f"CSR denied for relation ID {MY_RELATION_ID}, "
                + f"DNS '{REQUESTED_SUBJECT}' already requested.",
                id="dns_san_previously_requested",
            ),
            pytest.param(
                {"dns": {}, "ip": {REQUESTED_SUBJECT: OTHER_RELATION_ID}, "oid": {}},
                f"CSR denied for relation ID {MY_RELATION_ID}, "
                + f"IP '{REQUESTED_SUBJECT}' already requested.",
                id="ip_subject_previously_requested",
            ),
            pytest.param(
                {"dns": {}, "ip": {}, "oid": {REQUESTED_SUBJECT: OTHER_RELATION_ID}},
                f"CSR denied for relation ID {MY_RELATION_ID}, "
                + f"OID '{REQUESTED_SUBJECT}' already requested.",
                id="oid_san_previously_requested",
            ),
        ],
    )
    def test_given_previous_requesters_when_evaluate_csr_then_denials_are_logged(
        self,
        requested_identifiers,
        expected,
        caplog
    ):
        filter = LimitToFirstRequester(requested_identifiers)
        filter.evaluate(CSR, MY_RELATION_ID, [])
        logs = [(record.levelname, record.module, record.message) for record in caplog.records]
        assert ("WARNING", "charm", expected) in logs

    def test_given_previous_requesters_when_evaluate_csr_then_approvals_are_not_logged(
        self,
        caplog
    ):
        filter = LimitToFirstRequester({})
        filter.evaluate(CSR, MY_RELATION_ID, [])
        logs = [(record.levelname, record.module, record.message) for record in caplog.records]
        assert len(logs) == 0
