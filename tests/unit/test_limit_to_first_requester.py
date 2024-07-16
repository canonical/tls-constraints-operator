# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
from random import choice

import pytest
from charm import LimitToFirstRequester
from charms.tls_certificates_interface.v3.tls_certificates import (
    RequirerCSR,
    generate_csr,
    generate_private_key,
)

MY_RELATION_ID = 1
OTHER_RELATION_ID = 2
PROVIDER_RELATION_ID = 999

REQUESTED_SUBJECT = "Test Subject"
REQUESTED_DNS = ["test-0.example.com", "test-internal.example.com"]
REQUESTED_IPS = ["2.2.2.2", "10.142.42.2"]
REQUESTED_OIDS = ["1.2.3.4.42.120", "1.2.3.3.42.121"]

PRIVATE_KEY = generate_private_key()
OLD_CSR = generate_csr(
    private_key=PRIVATE_KEY,
    subject=REQUESTED_SUBJECT,
    sans_dns=REQUESTED_DNS,
    sans_ip=REQUESTED_IPS,
    sans_oid=REQUESTED_OIDS,
    organization="Example inc.",
    email_address="admin@example.com",
    country_name="CA",
)
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
RESERVED_SUBJECTS = [f"Reserved{i}" for i in range(4)]
RESERVED_DNS = [f"reserved{i}.example.com" for i in range(4)]
RESERVED_IPS = [f"10.0.0.{i}" for i in range(4)]
RESERVED_OIDS = [f"1.2.3.4.42.20{i}" for i in range(4)]
RESERVED_CSRS = [
    generate_csr(
        private_key=PRIVATE_KEY,
        subject=RESERVED_SUBJECTS[0],
        organization="Example inc.",
        email_address="admin@example.com",
        country_name="CA",
    ),
    generate_csr(
        private_key=PRIVATE_KEY,
        subject=RESERVED_SUBJECTS[1],
        sans_dns=RESERVED_DNS,
        organization="Example inc.",
        email_address="admin@example.com",
        country_name="CA",
    ),
    generate_csr(
        private_key=PRIVATE_KEY,
        subject=RESERVED_SUBJECTS[2],
        sans_ip=RESERVED_IPS,
        organization="Example inc.",
        email_address="admin@example.com",
        country_name="CA",
    ),
    generate_csr(
        private_key=PRIVATE_KEY,
        subject=RESERVED_SUBJECTS[3],
        sans_oid=RESERVED_OIDS,
        organization="Example inc.",
        email_address="admin@example.com",
        country_name="CA",
    ),
]


ALLOWED_CSRS = [
    RequirerCSR(
        relation_id=PROVIDER_RELATION_ID,
        application_name="other_app",
        unit_name="other_app/0",
        csr=csr.decode("utf-8"),
        is_ca=False,
    )
    for csr in RESERVED_CSRS
]

REQUIRER_CSRS = [
    RequirerCSR(
        relation_id=OTHER_RELATION_ID,
        application_name="other_app",
        unit_name="other_app/0",
        csr=csr.decode("utf-8"),
        is_ca=False,
    )
    for csr in RESERVED_CSRS
]

OLD_REQUIRER_CSR = RequirerCSR(
    relation_id=MY_RELATION_ID,
    application_name="my_app",
    unit_name="my_app/0",
    csr=OLD_CSR.decode("utf-8"),
    is_ca=False,
)


class TestLimitToFirstRequester:
    @pytest.mark.parametrize(
        "csr,relation_id,expected",
        [
            pytest.param(CSR, MY_RELATION_ID, True, id="previous_requesters_do_not_match"),
            pytest.param(
                generate_csr(private_key=PRIVATE_KEY, subject=choice(RESERVED_DNS)),
                MY_RELATION_ID,
                False,
                id="dns_subject_previously_requested",
            ),
            pytest.param(
                generate_csr(private_key=PRIVATE_KEY, subject=choice(RESERVED_IPS)),
                MY_RELATION_ID,
                False,
                id="ip_subject_previously_requested",
            ),
            pytest.param(
                generate_csr(private_key=PRIVATE_KEY, subject=choice(RESERVED_OIDS)),
                MY_RELATION_ID,
                False,
                id="oid_subject_previously_requested",
            ),
            pytest.param(
                generate_csr(
                    private_key=PRIVATE_KEY,
                    subject=REQUESTED_SUBJECT,
                    sans_dns=[choice(RESERVED_DNS)],
                ),
                MY_RELATION_ID,
                False,
                id="dns_san_previously_requested",
            ),
            pytest.param(
                generate_csr(
                    private_key=PRIVATE_KEY,
                    subject=REQUESTED_SUBJECT,
                    sans_ip=[choice(RESERVED_IPS)],
                ),
                MY_RELATION_ID,
                False,
                id="ip_san_previously_requested",
            ),
            pytest.param(
                generate_csr(
                    private_key=PRIVATE_KEY,
                    subject=REQUESTED_SUBJECT,
                    sans_oid=[choice(RESERVED_OIDS)],
                ),
                MY_RELATION_ID,
                False,
                id="oid_san_previously_requested",
            ),
            pytest.param(
                generate_csr(private_key=PRIVATE_KEY, subject=choice(RESERVED_DNS)),
                OTHER_RELATION_ID,
                True,
                id="dns_subject_previously_requested_by_us",
            ),
            pytest.param(
                generate_csr(private_key=PRIVATE_KEY, subject=choice(RESERVED_IPS)),
                OTHER_RELATION_ID,
                True,
                id="ip_subject_previously_requested_by_us",
            ),
            pytest.param(
                generate_csr(private_key=PRIVATE_KEY, subject=choice(RESERVED_OIDS)),
                OTHER_RELATION_ID,
                True,
                id="oid_subject_previously_requested_by_us",
            ),
            pytest.param(
                generate_csr(
                    private_key=PRIVATE_KEY,
                    subject=REQUESTED_SUBJECT,
                    sans_dns=[choice(RESERVED_DNS)],
                ),
                OTHER_RELATION_ID,
                True,
                id="dns_san_previously_requested_by_us",
            ),
            pytest.param(
                generate_csr(
                    private_key=PRIVATE_KEY,
                    subject=REQUESTED_SUBJECT,
                    sans_ip=[choice(RESERVED_IPS)],
                ),
                OTHER_RELATION_ID,
                True,
                id="ip_san_previously_requested_by_us",
            ),
            pytest.param(
                generate_csr(
                    private_key=PRIVATE_KEY,
                    subject=REQUESTED_SUBJECT,
                    sans_oid=[choice(RESERVED_OIDS)],
                ),
                OTHER_RELATION_ID,
                True,
                id="oid_san_previously_requested_by_us",
            ),
        ],
    )
    def test_given_previous_requesters_when_evaluate_csr_then_csr_is_allowed_or_denied(
        self, csr, relation_id, expected
    ):
        filter = LimitToFirstRequester(allowed_csrs=ALLOWED_CSRS)
        assert filter.evaluate(csr, relation_id, REQUIRER_CSRS) is expected

    @pytest.mark.parametrize(
        "csr,expected",
        [
            pytest.param(
                generate_csr(private_key=PRIVATE_KEY, subject=RESERVED_SUBJECTS[0]),
                f"CSR denied for relation ID {MY_RELATION_ID}, "
                + f"DNS '{RESERVED_SUBJECTS[0]}' already requested.",
                id="dns_san_previously_requested",
            ),
            pytest.param(
                generate_csr(private_key=PRIVATE_KEY, subject=RESERVED_DNS[0]),
                f"CSR denied for relation ID {MY_RELATION_ID}, "
                + f"DNS '{RESERVED_DNS[0]}' already requested.",
                id="dns_san_previously_requested",
            ),
            pytest.param(
                generate_csr(private_key=PRIVATE_KEY, subject=RESERVED_IPS[0]),
                f"CSR denied for relation ID {MY_RELATION_ID}, "
                + f"IP '{RESERVED_IPS[0]}' already requested.",
                id="ip_subject_previously_requested",
            ),
            pytest.param(
                generate_csr(private_key=PRIVATE_KEY, subject=RESERVED_OIDS[0]),
                f"CSR denied for relation ID {MY_RELATION_ID}, "
                + f"OID '{RESERVED_OIDS[0]}' already requested.",
                id="oid_san_previously_requested",
            ),
        ],
    )
    def test_given_previous_requesters_when_evaluate_csr_then_denials_are_logged(
        self, csr, expected, caplog
    ):
        filter = LimitToFirstRequester(allowed_csrs=ALLOWED_CSRS)
        filter.evaluate(csr, MY_RELATION_ID, REQUIRER_CSRS)
        logs = [(record.levelname, record.module, record.message) for record in caplog.records]
        assert ("WARNING", "charm", expected) in logs

    def test_given_previous_requesters_when_evaluate_csr_then_approvals_are_not_logged(
        self, caplog
    ):
        filter = LimitToFirstRequester(allowed_csrs=[])
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
        filter = LimitToFirstRequester(allowed_csrs=[])
        assert filter.evaluate(csr, MY_RELATION_ID, []) is True
