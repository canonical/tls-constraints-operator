#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm responsible for distributing certificates through relationship.

Certificates are provided by the operator trough Juju configs.
"""

import logging

from ops.charm import CharmBase, InstallEvent
from ops.main import main
from ops.model import ActiveStatus

logger = logging.getLogger(__name__)


class TLSConstraintsCharm(CharmBase):
    """Main class to handle Juju events."""

    def __init__(self, *args):
        """Observes config change and certificate request events."""
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)

    def _on_install(self, event: InstallEvent) -> None:
        """Handles the install event.

        The charm will be in Active Status and ready to handle actions.

        Args:
            event (InstallEvent): Juju event.

        Returns:
            None
        """
        self.unit.status = ActiveStatus()


if __name__ == "__main__":
    main(TLSConstraintsCharm)
