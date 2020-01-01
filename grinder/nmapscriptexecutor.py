#!/usr/bin/env python3
from pathlib import Path
from pathlib import PurePath

from grinder.nmapconnector import NmapConnector
from grinder.defaultvalues import DefaultValues
from grinder.decorators import exception_handler
from grinder.errors import GrinderScriptExecutorRunScriptError


class NmapScriptExecutor:
    @staticmethod
    @exception_handler(expected_exception=GrinderScriptExecutorRunScriptError)
    def run_script(host_info, nse_script, host_timeout=60) -> dict or None:
        """
        This function and class provide methods to run custom .nse
        scripts on particular hosts. Note - this scripts will be
        executed one by one for every host. Arguments of script
        execution can be fixed in Nmap connector call.
        :param host_info: information about current host
        :param nse_script: .nse script to run on host
        :param host_timeout: maximum timeout in seconds per host scan
        :return: results of script execution
        """
        if not (
            isinstance(nse_script, str)
            and (nse_script.endswith(".nse") or nse_script.endswith(".lua"))
        ):
            return
        nmap_script_name = PurePath(nse_script).stem
        script_path = (
            Path(".")
            .joinpath(DefaultValues.CUSTOM_SCRIPTS_DIRECTORY)
            .joinpath(DefaultValues.NSE_SCRIPTS_DIRECTORY)
            .joinpath(nse_script)
        )
        nm = NmapConnector()
        nm.scan(
            host=host_info.get("ip"),
            arguments=f"-Pn -sV -T4 --host-timeout {int(host_timeout)*1000}ms --script=./{str(script_path)}",
            ports=str(host_info.get("port")),
            sudo=False,
        )
        results = nm.get_results()

        script_execution_res = {}
        host_scan_results = results.get(host_info.get("ip"))
        if not host_scan_results:
            return
        host_scan_tcp = host_scan_results.get("tcp")
        if not host_scan_tcp:
            return
        for port, info in host_scan_tcp.items():
            script_list = info.get("script")
            if not script_list:
                continue
            script_info = script_list.get(nmap_script_name)
            if not script_info:
                continue
            script_execution_res.update({port: script_info})
        return script_execution_res
