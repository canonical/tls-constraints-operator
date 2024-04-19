#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm responsible for distributing certificates through relationship.

Certificates are provided by the operator through Juju configs.
"""

import logging
import re
from typing import Literal, Optional, Protocol

from charms.tls_certificates_interface.v3.tls_certificates import (
    AllCertificatesInvalidatedEvent,
    CertificateAvailableEvent,
    CertificateCreationRequestEvent,
    CertificateInvalidatedEvent,
    CertificateRevocationRequestEvent,
    RequirerCSR,
    TLSCertificatesProvidesV3,
    TLSCertificatesRequiresV3,
)
from cryptography import x509
from ops.charm import CharmBase
from ops.framework import EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

logger = logging.getLogger(__name__)

RELATION_NAME_TO_TLS_REQUIRER = "certificates-downstream"
RELATION_NAME_TO_TLS_PROVIDER = "certificates-upstream"


class CsrFilter(Protocol):
    """Protocol class defining a CSR filter for applying constraints."""

    def evaluate(self, csr: bytes, relation_id: int, requirer_csrs: list[RequirerCSR]) -> bool:
        """Evaluate if the provided CSR should be allowed.

        Args:
            csr (bytes): CSR to evaluate
            relation_id (int): ID of the relation sending the CSR
            requirer_csrs (list): All requirer CSRs received for comparison

        Returns:
            bool: True if the CSR is allowed, False otherwise.

        """
        ...


class LimitToOneRequest:
    """Filter the CSR so as to only allow a single request from any relation ID."""

    def evaluate(self, csr: bytes, relation_id: int, requirer_csrs: list[RequirerCSR]) -> bool:
        """Accept CSR if its the first CSR of a relation or the renewal of the existing CSR."""
        relevant_csrs = [csr for csr in requirer_csrs if csr.relation_id == relation_id]
        if len(relevant_csrs) > 1:
            logger.warning(
                "Denied CSR for relation_id: %d. Only a single CSR is allowed for application.",
                relation_id,
            )
            return False
        return True


class AllowedFields:
    """Filter the CSR so as to only allow CSRs that match the given regexes for the CSR fields."""

    COMMON_NAME_OID = x509.OID_COMMON_NAME
    ORGANIZATION_OID = x509.OID_ORGANIZATION_NAME
    EMAIL_OID = x509.OID_EMAIL_ADDRESS
    COUNTRY_CODE_OID = x509.OID_COUNTRY_NAME

    def __init__(self, filters: dict):
        self.field_filters = filters

    def _evaluate_subject(
        self,
        challenge: str,
        subject: x509.Name,
        oid: x509.ObjectIdentifier,
        field_optional: bool = False,
    ) -> str:
        pattern = re.compile(challenge)
        name_attributes = subject.get_attributes_for_oid(oid)
        if not field_optional and not name_attributes:
            return "field not found"
        if any(not pattern.match(str(val.value)) for val in name_attributes):
            return "field validation failed"
        return ""

    def _evaluate_sans(
        self, challenge: str, san: x509.SubjectAlternativeName, type: Literal["dns", "ip", "oid"]
    ) -> str:
        pattern = re.compile(challenge)
        match type:
            case "dns":
                dn_list = san.get_values_for_type(x509.DNSName)
            case "ip":
                dn_list = [str(val) for val in san.get_values_for_type(x509.IPAddress)]
            case "oid":
                dn_list = [val.dotted_string for val in san.get_values_for_type(x509.RegisteredID)]

        for dn in dn_list:
            if not pattern.match(dn):
                return "field validation failed"
        return ""

    def evaluate(self, csr: bytes, relation_id: int, requirer_csrs: list[RequirerCSR]) -> bool:  # noqa: C901
        """Accept CSR only if the given CSR passes the field regex matches."""
        csr_object = x509.load_pem_x509_csr(csr)
        san = csr_object.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        subject = csr_object.subject
        errors = []
        if challenge := self.field_filters.get("allowed-dns"):
            if err := self._evaluate_sans(challenge, san, "dns"):
                errors.append(f"error with dns in san: {err}")
        if challenge := self.field_filters.get("allowed-ips"):
            if err := self._evaluate_sans(challenge, san, "ip"):
                errors.append(f"error with ip in san: {err}")
        if challenge := self.field_filters.get("allowed-oids"):
            if err := self._evaluate_sans(challenge, san, "oid"):
                errors.append(f"error with oid in san: {err}")
        if challenge := self.field_filters.get("allowed-common-name"):
            if err := self._evaluate_subject(challenge, subject, self.COMMON_NAME_OID):
                errors.append(f"error with common name: {err}")
        if challenge := self.field_filters.get("allowed-organization"):
            if err := self._evaluate_subject(challenge, subject, self.ORGANIZATION_OID):
                errors.append(f"error with organization: {err}")
        if challenge := self.field_filters.get("allowed-email"):
            if err := self._evaluate_subject(challenge, subject, self.EMAIL_OID):
                errors.append(f"error with email: {err}")
        if challenge := self.field_filters.get("allowed-country-code"):
            if err := self._evaluate_subject(challenge, subject, self.COUNTRY_CODE_OID):
                errors.append(f"error with country code: {err}")
        if errors:
            logger.warning(
                "CSR from relation id %s failed regex validation for the following fields:",
                relation_id,
            )
            for err in errors:
                logger.warning("%s", err)
            return False
        return True


class TLSConstraintsCharm(CharmBase):
    """Main class to handle Juju events."""

    def __init__(self, *args):
        """Set up charm integration handlers and observe Juju events."""
        super().__init__(*args)
        self.certificates_provider = TLSCertificatesRequiresV3(
            self,
            RELATION_NAME_TO_TLS_PROVIDER,
        )
        self.certificates_requirers = TLSCertificatesProvidesV3(
            self,
            RELATION_NAME_TO_TLS_REQUIRER,
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
        csr = event.certificate_signing_request.encode()
        if self._is_certificate_allowed(csr, event.relation_id):
            self.certificates_provider.request_certificate_creation(csr, event.is_ca)
        else:
            logger.warning(
                "Certificate Request for relation ID %d was denied. Details in previous logs.",
                event.relation_id,
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

    def _is_certificate_allowed(self, csr: bytes, relation_id: int) -> bool:
        """Decide if the certificate should be allowed.

        Args:
            csr (bytes): Certificate Signing Request to validate
            relation_id (int): Relation ID that sent the CSR

        Returns:
            True if the certificate should be allowed, False otherwise
        """
        filters = self._get_csr_filters()
        all_requirers_csrs = self.certificates_requirers.get_requirer_csrs()
        if not all(filter.evaluate(csr, relation_id, all_requirers_csrs) for filter in filters):
            return False
        return True

    def _get_csr_filters(self) -> list[CsrFilter]:
        """Get all CsrFilters to apply.

        The individual filters are instantiated based on the charm configuration.

        Returns:
            list of CsrFilters to apply
        """
        filters = []
        if self.config.get("limit-to-one-request", None):
            filters.append(LimitToOneRequest())

        field_filters = {}
        for challenge in (
            "allowed-dns",
            "allowed-ips",
            "allowed-oids",
            "allowed-common-name",
            "allowed-organizations",
            "allowed-email",
            "allowed-country-code",
        ):
            if challenge := self.config.get(challenge):
                field_filters[challenge] = challenge
        if len(field_filters.items()) > 0:
            filters.append(AllowedFields(field_filters))

        return filters


if __name__ == "__main__":
    main(TLSConstraintsCharm)  # pragma: nocover
