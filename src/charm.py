#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm responsible for distributing certificates through relationship.

Certificates are provided by the operator through Juju configs.
"""

import logging
from typing import Optional

from charms.tls_certificates_interface.v3.tls_certificates import (
    AllCertificatesInvalidatedEvent,
    CertificateAvailableEvent,
    CertificateCreationRequestEvent,
    CertificateInvalidatedEvent,
    CertificateRevocationRequestEvent,
    TLSCertificatesProvidesV3,
    TLSCertificatesRequiresV3,
)
from ops.charm import CharmBase
from ops.framework import EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

logger = logging.getLogger(__name__)

RELATION_NAME_TO_TLS_REQUIRER = "certificates-downstream"
RELATION_NAME_TO_TLS_PROVIDER = "certificates-upstream"


class TLSConstraintsCharm(CharmBase):
    """Main class to handle Juju events."""

    def __init__(self, *args):
        """Set up charm integration handlers and observe Juju events."""
        super().__init__(*args)
        self.certificates_provider = TLSCertificatesRequiresV3(
            self, RELATION_NAME_TO_TLS_PROVIDER,
        )
        self.certificates_requirers = TLSCertificatesProvidesV3(
            self, RELATION_NAME_TO_TLS_REQUIRER,
        )
        self.framework.observe(self.on.install, self._update_status)
        self.framework.observe(self.on.update_status, self._update_status)
        self.framework.observe(self.on.certificates_upstream_relation_joined, self._update_status)
        self.framework.observe(
            self.on.certificates_downstream_relation_joined,
            self._update_status,
        )
        self.framework.observe(
            self.certificates_requirers.on.certificate_creation_request,
            self._on_certificate_creation_request,
        )
        self.framework.observe(
            self.certificates_requirers.on.certificate_revocation_request,
            self._on_certificate_revocation_request,
        )
        self.framework.observe(
            self.certificates_provider.on.certificate_available,
            self._on_certificate_available,
        )
        self.framework.observe(
            self.certificates_provider.on.certificate_invalidated,
            self._on_certificate_invalidated,
        )
        self.framework.observe(
            self.certificates_provider.on.all_certificates_invalidated,
            self._on_all_certificates_invalidated,
        )

    def _update_status(self, event: EventBase) -> None:
        """Handle charm events that need to update the status.

        The charm will be in Active Status when related to a TLS Provider
        and Blocked status otherwise.

        Args:
            event (EventBase): Juju event.

        Returns:
            None
        """
        if not self.model.get_relation(RELATION_NAME_TO_TLS_PROVIDER):
            self.unit.status = BlockedStatus("Need a relation to a TLS certificates provider")
            return
        self.unit.status = ActiveStatus()

    def _on_certificate_creation_request(self, event: CertificateCreationRequestEvent) -> None:
        """Handle certificate creation request events.

        If a TLS provider is not integrated to this charm, the event will be
        deferred and the status will be Blocked.
        Otherwise, the request will be forwarded to the provider.

        Args:
            event (CertificateCreationRequestEvent): Event containing the request

        Returns:
            None
        """
        if not self.model.get_relation(RELATION_NAME_TO_TLS_PROVIDER):
            event.defer()
            self.unit.status = BlockedStatus("Need a relation to a TLS certificates provider")
            return
        self.certificates_provider.request_certificate_creation(
            event.certificate_signing_request.encode(), event.is_ca
        )

    def _on_certificate_revocation_request(self, event: CertificateRevocationRequestEvent) -> None:
        """Handle certificate revocation request events.

        In the unlikely case a TLS provider is not integrated to this charm,
        the status will be blocked, and this event will be ignored.
        Otherwise, forward the revocation request to the provider.

        Args:
            event (CertificateRevocationRequestEvent): Event containing the request

        Returns:
            None
        """
        if not self.model.get_relation(RELATION_NAME_TO_TLS_PROVIDER):
            self.unit.status = BlockedStatus("Need a relation to a TLS certificates provider")
            return
        self.certificates_provider.request_certificate_revocation(
            event.certificate_signing_request.encode()
        )

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Handle certificate available events.

        Find the relation ID matching the CSR and forward the received
        certificate to that relation.
        If a relation ID is not found, log an error and ignores the event.

        Args:
            event (CertificateAvailableEvent): Event containing the certificate

        Returns:
            None
        """
        relation_id = self._get_relation_id_for_csr(event.certificate_signing_request)
        if not relation_id:
            logger.error(
                "Could not find the relation for CSR: %s.",
                event.certificate_signing_request,
            )
            return
        self.certificates_requirers.set_relation_certificate(
            certificate=event.certificate,
            certificate_signing_request=event.certificate_signing_request,
            ca=event.ca,
            chain=event.chain,
            relation_id=relation_id,
        )

    def _on_certificate_invalidated(self, event: CertificateInvalidatedEvent) -> None:
        """Handle certificate invalidated events.

        If the certificate is invalidated because it expired, ignore the event
        and let the requirer handle it properly. Otherwise, calls the TLS
        library to revoke the certificate to the requirer.

        Args:
            event (CertificateInvalidatedEvent): Event for invalidated certificate

        Returns:
            None
        """
        if event.reason == "expired":
            return
        self.certificates_requirers.remove_certificate(event.certificate)

    def _on_all_certificates_invalidated(self, event: AllCertificatesInvalidatedEvent) -> None:
        """Handle all certificates invalidated events.

        Revokes all certificates.

        Args:
            event (AllCertificatesInvalidatedEvent): Event for all certificates invalidated

        Returns:
            None
        """
        self.certificates_requirers.revoke_all_certificates()

    def _get_relation_id_for_csr(self, csr: str) -> Optional[int]:
        """Find the relation ID that sent the provided CSR.

        This should return a single relation ID, otherwise it means multiple
        applications requested the same certificate using the same private
        key. In that case, we log an error and return None.

        Args:
            csr (str): Certificate Signing Request to search

        Returns:
            Relation ID (int) or None
        """
        all_requirers_csrs = self.certificates_requirers.get_requirer_csrs()
        relation_ids = {
            requirer_csr.relation_id
            for requirer_csr in all_requirers_csrs
            if requirer_csr.csr == csr
        }
        if not relation_ids:
            return None
        if len(relation_ids) > 1:
            logger.error(
                "Multiple requirers have the same CSR. Cannot choose one between relation IDs: %s",  # noqa: E501
                relation_ids,
            )
            return None
        return relation_ids.pop()


if __name__ == "__main__":
    main(TLSConstraintsCharm)  # pragma: nocover
