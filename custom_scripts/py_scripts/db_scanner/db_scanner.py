#!/usr/bin/env python3

import pprint
from pymongo.errors import (
    ServerSelectionTimeoutError,
    ConfigurationError,
    AutoReconnect,
    OperationFailure,
    NetworkTimeout,
    CursorNotFound,
    InvalidName,
)
import pymongo

import traceback
import re

from collections.abc import Iterable
from itertools import groupby
from json import load
from bson.json_util import dumps
from bson.errors import InvalidBSON
from os import listdir
from pathlib import Path


class DBScannerDefaultValues:
    JSON_HOSTS = "hosts_for_scan.json"
    RESULTS_DIRECTORY = Path("results/db_scanner")
    CRITICAL_INFORMATION = [
        r"(?<!is)[aA]dmin",
        r"(?<![iI]d)(?<![iI]s)[mM]ail(?![tT]ime)(?![tT]itle)(?![tT]emplate)",
        r"(?<![fF]ile)(?<![sS]tatus)[uU]ser_*(?![iI]d)(?![lL]evel)(?![lL]ist)(?![tT]ype)",
        # (?=[nN]ame)* ?? (?<![sS]hipping)
        r"[aA]ccount(?![nN]um)",
        r"[pP]assword",  # (?<=[eE]ncrypted)*_*
        r"(?<![fF]ile)(?<![tT]ask)(?<![rR]oom)(?<![lL]evel)(?<![tT]able)(?<![gG]roup)[nN]ame(?![iI]d)",
        # (?<=[sS]ur)*(?<=[fF]irst)*(?<=[lL]ast)*(?<=[uU]ser)*
        r"\[nN]umber",
        r"(?<![iI])[pP]hone",
        r"[mM]obile",
        r"[sS]alt",
        r"[kK]ey",  # (?<![sS]har)
        r"(?<!skr)(?<!sk)(?<![tT]r)(?<![dD]escr)(?<![cC]l)(?<![mM]ult)(<?![eE]q)(<?![pP]rinz)(?<![eE]ll)(?<![pP]hil)(?<!h)(?<!v)(?<![tT]ool)[iI]p(?![lL]ine)(?![pP]hthonge)",
        # (?<=[cC]lient)*_* ?? (?<![zZ])
        r"cred",  # ?? (?!it)
        r"[aA]ddr",
        r"[dD]evice_*(?![iI]d)",
        r"[nN]ick(?!el)",
        r"[mM]a[cC]*(?!ge)(?!p)(?!x)(?!rk)(?!ll)(?!na)(?!st)(?!in)(?!t)(?!k)",
    ]
    CRITICAL_INFORMATION_VALUES = [
        {r"'+'*'('*[0-9][\s-]*'('*[0-9]{2,3,4})*[\s-]*[0-9]{}-*[0-9]{}{{10,11}"},
        {r"[a-zA-Z_ ]*"},
        {r"[0-9]{1,2,3}'.'[0-9]{1,2,3}'.'[0-9]{1,2,3}'.'[0-9]{1,2,3}"},
    ]
    JSON_RESULTS = "results_db.json"


def load_hosts(filename: str = DBScannerDefaultValues.JSON_HOSTS) -> list:
    """
    Load hosts from the file (useful when it's separated with Grinder)
    :param filename: filename of file with hosts
    :return: list of IP-addresses (for this case port is defined)
    """
    ip_list = []
    with open(filename, mode="r") as json_hosts:
        result_list = load(json_hosts)
    for value in result_list:
        if "ip" in value:
            ip_list.append(value["ip"])
    return ip_list


def save_results(
    host_dictionary: dict,
    filename: str = DBScannerDefaultValues.RESULTS_DIRECTORY.joinpath(
        DBScannerDefaultValues.JSON_RESULTS
    ),
) -> None:
    """
    Save results from execution to assigned file
    :param host_dictionary: scanning results
    :param filename: filename of resulting file
    :return: None
    """
    host_result = dumps(host_dictionary, indent=4)
    with open(filename, mode="a") as fd:
        fd.write(host_result + "\n")


def find_values_by_key(document: dict or list) -> dict or list or None:
    """
    Find different possible critical information by set regular expressions
    :param document: document from the database
    :return: found possible critical data
    """
    # print(type(document), document)
    document_list = {}
    for d in document:
        # print(f"doc is {d} and type is {type(d)} of value's {type(document[d])}")
        if not isinstance(document[d], list and dict):
            for info in DBScannerDefaultValues.CRITICAL_INFORMATION:
                # print(info, d)
                regular = re.findall(f"{info}", d)
                if len(regular) > 0:
                    if isinstance(document[d], int or float):
                        if document[d] != 0:
                            document_list.update({f"{d}": document[d]})
                    if document[d] not in ["", None, [], {}]:
                        document_list.update({f"{d}": document[d]})
                    break
        else:
            if isinstance(document[d], list):
                for item in document[d]:
                    # print(f"item is: {item}, type is: {type(item)}")
                    if type(item) == list:
                        for value in item:
                            if isinstance(value, dict):
                                result_list = find_values_by_key(value)
                                # print(f"result list: {result_list}")
                                if result_list is not None:
                                    document_list.update({value: result_list})
                    if isinstance(item, dict):
                        result_list = find_values_by_key(item)
                        # print(f"result list: {result_list}")
                        if result_list is not None:
                            document_list.update({item: result_list})
            if isinstance(document[d], dict):
                result_list = find_values_by_key(document[d])
                # print(f"doc type is {type(document[d])} and result's is {type(result_list)}")
                # print(f"doc is {document[d]} and result is {result_list}")
                if result_list is not None:
                    document_list.update(result_list)
    if len(document_list) == 0:
        return None
    # new_list = list(k for k, _ in groupby(document_list))
    # print("ok, here we are: ", document_list)
    return document_list


# TODO: add regular expressions for finding data by value
# TODO: restrict the connection's timeout in some ways
def connect_to_db(ip_value: str) -> (dict or None, Exception or None):
    """
    Connect to PyMongoDB and look for possible critical information
    :param ip_value: IP-address of host without authentication
    :return: founded info and caught exception, if something occurred
    """
    port = 27017
    try:
        client = pymongo.MongoClient(
            ip_value, port, serverSelectionTimeoutMS=2500, socketTimeoutMS=300000
        )  # , heartbeatFrequencyMS=2500
    except ServerSelectionTimeoutError as err:
        print(f"Host was unreachable: {ip_value} with {err}")
        return None, err
    if client is not None:
        try:
            db_names = client.list_database_names()
        except (
            ServerSelectionTimeoutError,
            ConfigurationError,
            NetworkTimeout,
            OperationFailure,
            KeyError,
        ) as err:
            print(f"Host was unreachable: {ip_value} with {err}")
            return None, err
        if db_names is None:
            return None
        host_dict = {
            "host": ip_value,
            "port": port,
            "version": client.server_info()["version"],
        }
        for db_num, db in enumerate(db_names):
            try:
                collection_names = client[db].list_collection_names()
            except (AutoReconnect, OperationFailure, KeyError, InvalidName) as err:
                print(f"Connection was over by server: {err}")
                if err is AutoReconnect:
                    if traceback.extract_tb(1) != ConnectionResetError:
                        continue
                return None, err
            for col_num, collection_name in enumerate(collection_names):
                # print(collection_name, " : ", col_num)
                if len(collection_names) == 0:
                    continue
                try:
                    host_dict[client[db][collection_name].name] = []
                except InvalidName as err:
                    print(f"Collection cannot be set: {err}")
                    continue
                try:
                    try:
                        docs_num = client[db][collection_name].count_documents({})
                    except AutoReconnect as err:  # ConnectionResetError
                        print(f"Connection was over by server: {err}")
                        return None, err
                    print(f"number of docs {docs_num} for {collection_name}")
                    cursor = client[db][collection_name].find(limit=100)
                    try:
                        for document in cursor:
                            document_list = find_values_by_key(document)
                            if document_list is not None:
                                host_dict[client[db][collection_name].name].append(
                                    document_list
                                )
                    except InvalidBSON as err:
                        print(f"Error occurred with decoding: {err}")
                        if len(host_dict[client[db][collection_name].name]) == 0:
                            host_dict.pop(client[db][collection_name].name)
                        return host_dict, err
                except (NetworkTimeout, CursorNotFound) as err:
                    print(f"Waiting of server is too long: {err}")
                    if len(host_dict[client[db][collection_name].name]) == 0:
                        host_dict.pop(client[db][collection_name].name)
                    save_results(host_dict)
                    client.close()
                    return host_dict, err
                if len(host_dict[client[db][collection_name].name]) == 0:
                    host_dict.pop(client[db][collection_name].name)
        save_results(host_dict)
        client.close()
        return host_dict
    else:
        return None


def connect_and_find_by_value():
    pass


def main(host_info: dict) -> dict:
    """
    Return critical data or something similar about host if it's possible
    :param host_info: information about host
    :return: dictionary with data
    """
    DBScannerDefaultValues.RESULTS_DIRECTORY.mkdir(exist_ok=True, parents=True)
    try:
        result, error = connect_to_db(host_info.get("ip"))
        if error is not None:
            return {"error": str(error)}
        if result is not None:
            return {"status": result}
    except Exception as err:
        return {"error": str(err)}


if __name__ == "__main__":
    ip_list = load_hosts()
    for ip_value in ip_list:
        result = connect_to_db(ip_value)
