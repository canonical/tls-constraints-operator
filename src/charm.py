#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm responsible for distributing certificates through relationship.

Certificates are provided by the operator trough Juju configs.
"""

import logging

from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import-not-found]  # noqa: E501
    TLSCertificatesRequiresV2,
)
from ops.charm import CharmBase, EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

logger = logging.getLogger(__name__)


class TLSConstraintsCharm(CharmBase):
    """Main class to handle Juju events."""

    def __init__(self, *args):
        """Observes config change and certificate request events."""
        super().__init__(*args)
        self.certificates_provider = TLSCertificatesRequiresV2(self, "certificates-provider")
        self.framework.observe(self.on.install, self._update_status)
        self.framework.observe(self.on.update_status, self._update_status)
        self.framework.observe(self.on.certificates_provider_relation_joined, self._update_status)

    def _update_status(self, event: EventBase) -> None:
        """Handles charm events that need to update the status.

        The charm will be in Active Status when related to a TLS Provider
        and Blocked status otherwise.

        Args:
            event (EventBase): Juju event.

        Returns:
            None
        """
        if not self.model.get_relation("certificates-provider"):
            self.unit.status = BlockedStatus("Waiting for TLS certificates provider relation")
            return
        self.unit.status = ActiveStatus()


if __name__ == "__main__":
    main(TLSConstraintsCharm)
