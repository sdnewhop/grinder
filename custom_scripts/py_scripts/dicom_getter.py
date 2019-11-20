#!/usr/bin/env python3

from pynetdicom import AE, QueryRetrievePresentationContexts
from pydicom.dataset import Dataset
from pprint import pprint


class DicomGetter:
    def __init__(self):
        """
        Init DICOM connector
        """
        self.ae = AE()
        self.ip = None
        self.port = None
        self.properties = list()

    def set_request_context(
        self, request_context: QueryRetrievePresentationContexts
    ) -> None:
        """
        Set request context for connection to DICOM
        :param request_context: context of connection
        :return: None
        """
        self.ae.requested_contexts = request_context

    def set_host(self, ip: str, port: int) -> None:
        """
        Set host to connect to
        :param ip: host ip
        :param port: host port
        :return: None
        """
        self.ip, self.port = ip, port

    def get_server_properties(self):
        """
        Get DICOM server properties
        :return: None
        """
        association = self.ae.associate(self.ip, self.port)
        if not association.is_established:
            return
        for context in association.accepted_contexts:
            try:
                transfer_syntaxes = [
                    syntax.name
                    for syntax in context.transfer_syntax
                    if context.transfer_syntax
                ] or []
            except:
                transfer_syntaxes = []
            context_data = {
                "Abstract Syntax": context.abstract_syntax.name,
                "Transfer Syntax(es)": transfer_syntaxes,
                "Result": context.result,
                "Status": context.status,
                "SCU Role": context.as_scu,
                "SCP Role": context.as_scp,
                "String Representation": str(context),
            }
            self.properties.append(context_data)
        association.release()
        return self.properties


def main(host_info: dict) -> list or dict:
    """
    Get DICOM server properties (accepted syntaxes and methods)
    :param host_info: host information
    :return: dictionary with data
    """
    dicom_getter = DicomGetter()
    dicom_getter.set_host(host_info.get("ip"), host_info.get("port"))
    dicom_getter.set_request_context(QueryRetrievePresentationContexts)
    try:
        return dicom_getter.get_server_properties()
    except Exception as unexp_err:
        return {"error": str(unexp_err)}
