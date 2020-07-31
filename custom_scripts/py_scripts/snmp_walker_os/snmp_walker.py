#!/usr/bin/env python3


from subprocess import check_output
from os import listdir
from pathlib import Path


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

    if f"{fxd_vendor}_{fxd_product}_{ip}_{fxd_community_string}.txt" in listdir(
        SnmpWalkerDefaultValues.RESULTS_PATH
    ):
        return True


def save_results(
    results: str, ip: str, community_string: str, vendor: str, product: str
) -> None:
    """
    Save result in txt file 'vendor_product_ip_communitystring.txt'
    :param results: results to save in *.txt file
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
        f"{fxd_vendor}_{fxd_product}_{ip}_{fxd_community_string}.txt"
    )
    with open(results_path, mode="w") as result_file:
        result_file.write(results)


def exec_with_params(
    command: list, ip: str, possible_community_string: str, vendor: str, product: str
) -> str or None:
    """
    Execute system snmpwalk command
    :param command: command to execute, snmpwalk with additional params
    :param ip: ip of the host
    :param possible_community_string: community string to connect with
    :param vendor: vendor related to the host
    :param product: product related to the host
    :return: results of snmpwalk in str representation or None
    """
    print(
        f"Start scanning host '{ip}', "
        f"product '{product}' of '{vendor}' "
        f"with community string '{possible_community_string}'"
    )
    print(f"Command to start: {' '.join(command)}")

    try:
        snmpwalk_results = check_output(command, universal_newlines=True, timeout=1200)
    except Exception as unexp_e:
        print(f"Caught called process error: {str(unexp_e)}")
        return

    print(f"Scanning of '{ip}' is completed")
    save_results(snmpwalk_results, ip, possible_community_string, vendor, product)
    return snmpwalk_results


def execute_snmpwalk(
    ip: str, vendor: str, product: str, community_strings: list = None
) -> None:
    """
    Prepare system snmpwalk command with additional things
    :param ip: ip of the host
    :param vendor: vendor related to the host
    :param product: product related to the host
    :param community_strings: list of community strings to connect with (public, private, etc.)
    :return: nothing
    """
    if community_strings is None:
        community_strings = ["public", "private"]
    for possible_community_string in community_strings:
        # Skip host if we have already scan it before
        if is_host_scanned(ip, possible_community_string, vendor, product):
            print(
                f"Host '{ip}' was already scanned with '{possible_community_string}' community string"
            )
            continue
        command = ["snmpwalk", "-v", "2c", "-c", possible_community_string, ip]
        exec_with_params(command, ip, possible_community_string, vendor, product)


def main(host_info: dict) -> dict:
    """
    Main SNMP-walker runner
    :param host_info: information about some host
    :return: empty dict
    """

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

    # SNMP-walker works with files basically, so it doesn't return
    # anything by default. But you can change this behavior and
    # return something that you need (for example, something that
    # can be found with regexps and so on).
    execute_snmpwalk(
        host_info.get("ip"), host_info.get("vendor"), host_info.get("product")
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
