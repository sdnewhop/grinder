#!/usr/bin/env python3

from easysnmp import snmp_walk
from json import dump
from pathlib import Path
from os import listdir


class SnmpWalkerDefaultValues:
    """
    Default values
    """

    RESULTS_PATH = Path(".").joinpath("results").joinpath("snmp_walker")


def is_host_scanned(
    ip: str, community_string: str, vendor: str, product: str
) -> bool or None:
    """
    Check if the host is already scanned
    :param ip: ip of the host
    :param community_string: community string
    :param vendor: vendor related to the host
    :param product: product related to the host
    :return: bool True or nothing
    """
    fxd_community_string = community_string.replace(".", "-")
    fxd_vendor = vendor.replace(" ", "-")
    fxd_product = product.replace(" ", "-")

    # Note: if you want to scan only 1 host for every vendor:product pair, uncomment
    # part under that note and comment current return-part

    # for file_name in listdir(SnmpWalkerDefaultValues.results_path):
    #     if f"{vendor}_{product}" in file_name:
    #         return True

    if f"{fxd_vendor}_{fxd_product}_{ip}_{fxd_community_string}.json" in listdir(
        SnmpWalkerDefaultValues.RESULTS_PATH
    ):
        return True


def save_results(
    results: dict or list, ip: str, community_string: str, vendor: str, product: str
) -> None:
    """
    Save result in json file 'vendor_product_ip_communitystring.json'
    :param results: results to save in *.json file
    :param ip: ip of the host
    :param community_string: successful community string
    :param vendor: vendor related to the host
    :param product: product related to the host
    :return: nothing
    """
    fxd_community_string = community_string.replace(".", "-")
    fxd_vendor = vendor.replace(" ", "-")
    fxd_product = product.replace(" ", "-")

    results_path = SnmpWalkerDefaultValues.RESULTS_PATH.joinpath(
        f"{fxd_vendor}_{fxd_product}_{ip}_{fxd_community_string}.json"
    )
    with open(results_path, mode="w") as result_file:
        dump(results, result_file, indent=4)


def main(host_info: dict, community_strings: list = None) -> dict:
    """
    Main easy-SNMP-walker runner
    :param community_strings: list of community strings to connect with (public, private, etc.)
    :param host_info: information about some host
    :return: nothing, empty dict
    """

    # Define default community string
    if community_strings is None:
        community_strings = ["public", "private"]

    # Create directory for results
    SnmpWalkerDefaultValues.RESULTS_PATH.mkdir(exist_ok=True, parents=True)

    # Note: it is an important part that Nmap must detect open UDP
    # port 161 to scan it with SNMP-walker, or in another way,
    # you can modify this part with check somehow.
    if (
        host_info.get("nmap_scan", {}).get("udp", {}).get("161", {}).get("state")
        != "open"
    ):
        return {}

    host_ip, host_vendor, host_product = (
        host_info.get("ip"),
        host_info.get("vendor"),
        host_info.get("product"),
    )
    for community_string in community_strings:
        if is_host_scanned(host_ip, community_string, host_vendor, host_product):
            continue
        combined_results = []
        try:
            walk_results = snmp_walk(hostname=host_ip, community="public", version=2)
        except Exception as unexp_e:
            print(f"Caught snmpwalk error: {str(unexp_e)}")
            return {}
        for walk_item in walk_results:
            combined_results.append(
                {
                    "oid": walk_item.oid,
                    "oid_index": walk_item.oid_index,
                    "snmp_type": walk_item.snmp_type,
                    "value": walk_item.value,
                }
            )
        save_results(
            combined_results, host_ip, community_string, host_vendor, host_product
        )
    return {}


if __name__ == "__main__":
    """
    Make test run for script
    """

    test_host_info = {
        "vendor": "VENDOR_NAME_HERE",
        "product": "PRODUCT_NAME_HERE",
        "ip": "HOST_IP_HERE",
        "nmap_scan": {"udp": {"161": {"state": "open"}}},
    }

    main(test_host_info)
