#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm responsible for distributing certificates through relationship.

Certificates are provided by the operator through Juju configs.
"""

import logging
import re
from itertools import chain
from typing import Literal, Optional, Protocol

from charms.tls_certificates_interface.v3.tls_certificates import (
    RequirerCSR,
    TLSCertificatesProvidesV3,
    TLSCertificatesRequiresV3,
)
from cryptography import x509
from cryptography.x509.oid import NameOID
from ops.charm import CharmBase, CollectStatusEvent
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


class LimitToFirstRequester:
    """Filter the CSR as to only allow the first requester to get a specific identifier."""

    DENY_MSG = "CSR denied for relation ID %d, %s '%s' already requested."

    def __init__(self, *, allowed_csrs: list[RequirerCSR]):
        self._allowed_csrs = allowed_csrs
        self._registered_dns: dict[str, int | None] = {}
        self._registered_ips: dict[str, int | None] = {}
        self._registered_oids: dict[str, int | None] = {}

    def _populate_previously_allowed_identifiers(self, requirer_csrs: list[RequirerCSR]) -> None:
        """Populate the previously allowed identifiers mapping.

        Goes through all the allowed CSRs, finding their DNS, IP and OIDs
        and adding them to the lookup table with the relation ID of the
        downstream relation that requested that CSR.

        Args:
            requirer_csrs: List of RequirerCSRs from the downstream relations
        Return:
            None
        """
        csr_to_id = {rc.csr: rc.relation_id for rc in requirer_csrs}

        for allowed_csr in self._allowed_csrs:
            relation_id = csr_to_id.get(allowed_csr.csr, None)
            csr_object = x509.load_pem_x509_csr(allowed_csr.csr.encode("utf-8"))
            subjects = [
                cn.value
                for cn in csr_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if isinstance(cn.value, str)
            ]
            try:
                san = csr_object.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value  # noqa: E501
            except x509.ExtensionNotFound:
                san = x509.SubjectAlternativeName([])
            for dns in chain(san.get_values_for_type(x509.DNSName), subjects):
                self._registered_dns[dns] = relation_id
            for ip in chain(san.get_values_for_type(x509.IPAddress), subjects):
                self._registered_ips[str(ip)] = relation_id
            for oid in chain(
                (
                    getattr(o, "dotted_string", "")
                    for o in san.get_values_for_type(x509.RegisteredID)
                ),  # noqa: E501
                subjects,
            ):
                self._registered_oids[oid] = relation_id

    def evaluate(self, csr: bytes, relation_id: int, requirer_csrs: list[RequirerCSR]) -> bool:
        """Accept the CSR if no other relation previously requested any covered identifiers.

        Identifiers that need to be unique are the Subject, all Subject Alternative Names,
        all Subject Alternative IPs and all Subject Alternative OIDs.
        """
        self._populate_previously_allowed_identifiers(requirer_csrs)
        csr_object = x509.load_pem_x509_csr(csr)
        subjects = [
            cn.value for cn in csr_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ]
        try:
            san = csr_object.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            san = x509.SubjectAlternativeName([])
        for dns in chain(san.get_values_for_type(x509.DNSName), subjects):
            if dns in self._registered_dns and self._registered_dns[dns] != relation_id:
                logger.warning(self.DENY_MSG, relation_id, "DNS", dns)
                return False
        for ip in chain(san.get_values_for_type(x509.IPAddress), subjects):
            if str(ip) in self._registered_ips and self._registered_ips[str(ip)] != relation_id:
                logger.warning(self.DENY_MSG, relation_id, "IP", ip)
                return False
        for oid in chain(
            (getattr(o, "dotted_string", "") for o in san.get_values_for_type(x509.RegisteredID)),
            subjects,
        ):
            if oid in self._registered_oids and self._registered_oids[oid] != relation_id:
                logger.warning(self.DENY_MSG, relation_id, "OID", oid)
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
        try:
            san = csr_object.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            san = x509.SubjectAlternativeName([])
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
                errors.append(f"error with email address: {err}")
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
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self.framework.observe(
            self.on.certificates_downstream_relation_joined,
            self._configure,
        )
        self.framework.observe(
            self.on.update_status,
            self._configure,
        )
        self.framework.observe(
            self.certificates_requirers.on.certificate_creation_request,
            self._configure,
        )
        self.framework.observe(
            self.certificates_requirers.on.certificate_revocation_request,
            self._configure,
        )
        self.framework.observe(
            self.certificates_provider.on.certificate_available,
            self._configure,
        )
        self.framework.observe(
            self.certificates_provider.on.certificate_invalidated,
            self._configure,
        )
        self.framework.observe(
            self.certificates_provider.on.all_certificates_invalidated,
            self._configure,
        )

    def _on_collect_status(self, event: CollectStatusEvent) -> None:
        """Handle charm events that need to update the status.

        The charm will be in Active Status when related to a TLS Provider
        and Blocked status otherwise.

        Args:
            event (CollectStatusEvent): Juju event.

        Returns:
            None
        """
        if not self.model.get_relation(RELATION_NAME_TO_TLS_PROVIDER):
            event.add_status(BlockedStatus("Need a relation to a TLS certificates provider"))
            return
        event.add_status(ActiveStatus())

    def _configure(self, _: EventBase):
        if not self.model.get_relation(RELATION_NAME_TO_TLS_PROVIDER):
            logger.info("Need a relation to a TLS certificates provider")
            return
        self._sync_certificate_creation_requests()
        self._sync_certificate_revocation_requests()
        self._sync_available_certificates()
        self._sync_invalidated_certificates()

    def _sync_certificate_creation_requests(self):
        """Handle certificate creation requests.

        Goes through all the outstanding certificate requests and
        forwards them to the provider if they are allowed.
        """
        outstanding_requests = self.certificates_requirers.get_outstanding_certificate_requests()
        for request in outstanding_requests:
            csr = request.csr.encode()
            if self._is_certificate_allowed(csr, request.relation_id):
                self.certificates_provider.request_certificate_creation(csr, request.is_ca)
            else:
                logger.warning(
                    "Certificate Request for relation ID %d was denied. Details in previous logs.",
                    request.relation_id,
                )

    def _sync_certificate_revocation_requests(self):
        """Handle certificate revocation requests.

        Goes through all the outstanding revocation requests and
        forwards them to the provider.
        """
        provider_certificates = self.certificates_requirers.get_certificates_for_which_no_csr_exists()
        for provider_certificate in provider_certificates:
            self.certificates_provider.request_certificate_revocation(provider_certificate.csr.encode())

    def _sync_available_certificates(self):
        """Handle certificate available.

        Goes through all the certificates available and forwards them
        to the appropriate requirer.
        """
        provider_certificates = self.certificates_provider.get_assigned_certificates()
        for provider_certificate in provider_certificates:
            relation_id = self._get_relation_id_for_csr(provider_certificate.csr)
            if not relation_id:
                logger.error(
                    "Could not find the relation for CSR: %s.",
                    provider_certificate.csr,
                )
                continue
            self.certificates_requirers.set_relation_certificate(
                certificate=provider_certificate.certificate,
                certificate_signing_request=provider_certificate.csr,
                ca=provider_certificate.ca,
                chain=provider_certificate.chain,
                relation_id=relation_id,
            )

    def _sync_invalidated_certificates(self):
        provider_certificates = self.certificates_provider.get_assigned_certificates()
        for provider_certificate in provider_certificates:
            relation_id = self._get_relation_id_for_csr(provider_certificate.csr)
            if not relation_id:
                logger.error(
                    "Could not find the relation for CSR: %s.",
                    provider_certificate.csr,
                )
                continue
            if provider_certificate.revoked:
                self.certificates_requirers.remove_certificate(
                    certificate=provider_certificate.certificate,
                )

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
        if self.config.get("limit-to-first-requester", False):
            filters.append(
                LimitToFirstRequester(allowed_csrs=self.certificates_provider.get_requirer_csrs())
            )

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
            if regex := self.config.get(challenge):
                field_filters[challenge] = regex
        if len(field_filters.items()) > 0:
            filters.append(AllowedFields(field_filters))
        logger.warning("Enabled filters: %s", filters)

        return filters


if __name__ == "__main__":
    main(TLSConstraintsCharm)  # pragma: nocover
