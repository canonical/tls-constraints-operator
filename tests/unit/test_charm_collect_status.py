#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import scenario
from ops.model import ActiveStatus, BlockedStatus

from tests.unit.fixtures import TLSConstraintsFixtures


class TestCharmCollectStatus(TLSConstraintsFixtures):
    def test_given_tls_relation_not_created_when_collect_unit_status_then_status_is_blocked(self):
        state_in = scenario.State()

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state=state_in)

        assert state_out.unit_status == BlockedStatus(
            "Need a relation to a TLS certificates provider"
        )

    def test_given_tls_relation_created_when_collect_unit_status_then_status_is_active(self):
        tls_relation = scenario.Relation(
            endpoint="certificates-upstream",
            interface="tls-certificates",
        )
        state_in = scenario.State(
            relations={tls_relation},
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state=state_in)

        assert state_out.unit_status == ActiveStatus()
