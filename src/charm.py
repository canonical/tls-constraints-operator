#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm responsible for distributing certificates through relationship.

Certificates are provided by the operator trough Juju configs.
"""

import logging
from typing import Optional

from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import-not-found]  # noqa: E501
    AllCertificatesInvalidatedEvent,
    CertificateAvailableEvent,
    CertificateCreationRequestEvent,
    CertificateInvalidatedEvent,
    CertificateRevocationRequestEvent,
    TLSCertificatesProvidesV2,
    TLSCertificatesRequiresV2,
)
from ops.charm import CharmBase, EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

logger = logging.getLogger(__name__)

PROVIDES_RELATION_NAME = "certificates-provides"
REQUIRES_RELATION_NAME = "certificates-requires"


class TLSConstraintsCharm(CharmBase):
    """Main class to handle Juju events."""

    def __init__(self, *args):
        """Setup charm integration handlers and observe Juju events."""
        super().__init__(*args)
        self.certificates_provider = TLSCertificatesRequiresV2(self, REQUIRES_RELATION_NAME)
        self.certificates_requirers = TLSCertificatesProvidesV2(self, PROVIDES_RELATION_NAME)
        self.framework.observe(self.on.install, self._update_status)
        self.framework.observe(self.on.update_status, self._update_status)
        self.framework.observe(self.on.certificates_requires_relation_joined, self._update_status)
        self.framework.observe(self.on.certificates_provides_relation_joined, self._update_status)
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
        """Handles charm events that need to update the status.

        The charm will be in Active Status when related to a TLS Provider
        and Blocked status otherwise.

        Args:
            event (EventBase): Juju event.

        Returns:
            None
        """
        if not self.model.get_relation(REQUIRES_RELATION_NAME):
            self.unit.status = BlockedStatus("Need a relation to a TLS certificates provider")
            return
        self.unit.status = ActiveStatus()

    def _on_certificate_creation_request(self, event: CertificateCreationRequestEvent) -> None:
        """Handles certificate creation request events.

        If a TLS provider is not integrated to this charm, the event will be
        defered and the status will be Blocked.
        Otherwise, the request will be forwarded to the provider.

        Args:
            event (CertificateCreationRequestEvent): Event containing the request

        Returns:
            None
        """
        if not self.model.get_relation(REQUIRES_RELATION_NAME):
            event.defer()
            self.unit.status = BlockedStatus("Need a relation to a TLS certificates provider")
            return
        self.certificates_provider.request_certificate_creation(
            event.certificate_signing_request.encode(), event.is_ca
        )

    def _on_certificate_revocation_request(self, event: CertificateRevocationRequestEvent) -> None:
        """Handles certificate revocation request events.

        In the unlikely case a TLS provider is not integrated to this charm,
        the status will be blocked, and this event will be ignored.
        Otherwise, forward the revocation request to the provider.

        Args:
            event (CertificateRevocationRequestEvent): Event containing the request

        Returns:
            None
        """
        if not self.model.get_relation(REQUIRES_RELATION_NAME):
            self.unit.status = BlockedStatus("Need a relation to a TLS certificates provider")
            return
        self.certificates_provider.request_certificate_revocation(
            event.certificate_signing_request.encode()
        )

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Handles certificate available events.

        Finds the relation ID matching the CSR and forwards the received
        certificate to that relation.
        If a relation ID is not found, logs an error and ignores the event.

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
        """Handles certificate invalidated events.

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
        """Handles all certificates invalidated events.

        Revokes all certificates.

        Args:
            event (AllCertificatesInvalidatedEvent): Event for all certificates invalidated

        Returns:
            None
        """
        self.certificates_requirers.revoke_all_certificates()

    def _get_relation_id_for_csr(self, csr: str) -> Optional[int]:
        """Finds the relation ID that sent the provided CSR.

        This should return a single relation ID, otherwise it means multiple
        applications requested the same certificate using the same private
        key. In that case, we log an error and return None.

        Args:
            csr (str): Certificate Signing Request to search

        Returns:
            Relation ID (int) or None
        """
        requirers_csrs = self.certificates_requirers.get_requirer_csrs()
        relation_ids: set[int] = set()
        for requirer_csrs in requirers_csrs:
            match requirer_csrs:
                case {
                    "relation_id": relation_id,
                    "unit_csrs": [{"certificate_signing_request": str(unit_csr)}],
                } if unit_csr == csr:  # type: ignore[has-type]
                    relation_ids.add(relation_id)
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
