# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import unittest

from ops import testing
from ops.model import ActiveStatus

from charm import TLSConstraintsCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(TLSConstraintsCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(True)
        self.harness.begin()

    def test_given_charm_when_install_then_status_is_active(self):
        self.harness.charm.on.install.emit()
        self.assertEqual(
            ActiveStatus(),
            self.harness.charm.unit.status,
        )
