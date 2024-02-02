# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import unittest

from ops import testing
from ops.model import ActiveStatus, BlockedStatus

from charm import TLSConstraintsCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(TLSConstraintsCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(True)
        self.harness.begin()

    def test_given_not_related_to_provider_when_on_install_then_status_is_blocked(self):
        self.harness.charm.on.install.emit()
        self.assertEqual(
            BlockedStatus("Waiting for TLS certificates provider relation"),
            self.harness.charm.unit.status,
        )

    def test_given_installed_when_related_to_tls_provider_then_status_is_active(self):
        relation_id = self.harness.add_relation(
            relation_name="certificates-provider",
            remote_app="certificates-provider",
        )
        self.harness.add_relation_unit(
            relation_id=relation_id,
            remote_unit_name="certificates-provider/0",
        )

        self.assertEqual(
            ActiveStatus(),
            self.harness.charm.unit.status,
        )
