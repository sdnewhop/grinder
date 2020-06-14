#!/usr/bin/env python3

from pymongo.errors import (
    ServerSelectionTimeoutError,
    ConfigurationError,
    AutoReconnect,
    OperationFailure,
    NetworkTimeout,
    CursorNotFound,
    InvalidName,
)
from pymongo import MongoClient, database
from json import load, dump, JSONDecodeError
from pathlib import Path
from re import findall
from traceback import extract_tb
from time import perf_counter


class DBScannerDefaultValues:
    MODULE_RESULTS = {}
    JSON_HOSTS = "hosts_for_scan.json"
    RESULTS_DIRECTORY = Path("results/db_scanner")
    TEMPORARY_RESULTS_DIRECTORY = RESULTS_DIRECTORY.joinpath("temporaries")
    CRITICAL_INFORMATION = [
        r"(?<!is)[aA]dmin",
        r"(?<![iI]d)(?<![iI]s)[mM]+ail(?![tT]ime)(?![tT]itle)(?![tT]emplate)",
        r"(?<![fF]ile)(?<![sS]tatus)(?<!message)[uU]+ser_?(?![iI][dD])(?![lL]evel)(?![lL]ist)(?![tT]ype)",
        r"(?<!_)[aA]ccount(?![nN]um)",
        r"[pP]assword",
        r"(?<!le)(?<!ask)(?<!oom)(?<!evel)(?<!roup)(?<!lass)(?!<ory)(?<!ost)(?<!and)(?<!ob)[nN]ame(?![iI][dD])",
        r"[nN]umber",
        r"(?<![iI])[pP]hone",
        r"[mM]+obile",
        r"[sS]alt",
        r"^(?!_)\w*[kK]+ey",
        r"cred",
        r"[aA]ddr",
        r"[dD]evice_*(?![iI][dD])",
        r"[nN]ick(?!el)",
        r"(?<![saeiw])[mM]+a[cC]+(?!d)(?!g)(?!p)(?!x)(?!rk)(?!ll)(?!n)(?!st)(?!in)(?!t)(?!k)",
    ]
    NOT_INCLUDED = r"_[iI]+[dD]+_?|[tT]+[iI]+[mM]+[eE]+|[cC]+ontent|[mM]+essage"
    CRITICAL_INFORMATION_VALUES = [
        r"[\w.-]+@[\w.-]+\.\w+",
        r"\(?[\+]?[1-9][\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}",
        r"\(?[\+]?[1-9][\s\-]?\(?\d{1}\)?[\s\-]?\d{3}[\s\-]?\d{3}[\s\-]?\d{3}",
        r"\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}",
        r"\d{4}[\s-]?\d{6}[\s-]?\d{5}",
        # r"\d{1,2}\s?\d{1,2}\s?\d{4}",
        r"(\\\\?([^\\\/]*[\\\/])*)([^\\\/]+)",
        r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}",
        r"^3[47][0-9]{13}",
        r"^((\d{5}-\d{4})|(\d{5})|([A-Z]\d[A-Z]\s\d[A-Z]\d))",
        r"^\d{3}-\d{2}-\d{3}-\d-\d{4}-\d{6}",
        r"^\d{20}",
        r"^\d{9}",
        r"^(\d{11})|(\d{3}\s\d{3}\s\d{3}\s\d{2})",
        r"^\d{13,15}",
    ]
    REGULARS_INFO = "".join(reg + "|" for reg in CRITICAL_INFORMATION)
    REGULARS_VALUES = "".join(reg + "|" for reg in CRITICAL_INFORMATION_VALUES)
    JSON_RESULTS = "results_db.json"
    MAX_TIME_OF_CONNECTION_IN_SECONDS = 300


class DBScannerException(Exception):
    def __init__(self, error_args: Exception or str):
        super().__init__(self)
        self._error_args = error_args

    @property
    def error_args(self):
        return self._error_args

    def __str__(self):
        return f"Error occurred in DBScanner module: {self._error_args}"


class DBScannerConnectionTimeout(DBScannerException):
    def __init__(self, error_args: Exception or str):
        super().__init__(error_args)


def load_hosts(filename: str = DBScannerDefaultValues.JSON_HOSTS) -> list:
    """
    Load hosts from the file (useful when it's separated with Grinder)
    :param filename: filename of file with hosts
    :return: list of IP-addresses (for this case port is defined)
    """
    with open(filename, mode="r") as json_hosts:
        result_list = load(json_hosts)
    return [value.get("ip") for value in result_list]


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
    with open(filename, mode="a") as result_file:
        dump(host_dictionary, result_file, indent=4)


def save_temporary_results(
    temporary_directory: Path = DBScannerDefaultValues.TEMPORARY_RESULTS_DIRECTORY,
) -> None:
    """
    Save results from execution to assigned temporary file
    :param temporary_directory: temporary filename of resulting file
    :return: None
    """
    ip_values = DBScannerDefaultValues.MODULE_RESULTS.keys()
    for ip in ip_values:
        filename = str(temporary_directory.joinpath(str(ip) + ".txt"))
        with open(filename, mode="a") as result_file:
            dump(
                DBScannerDefaultValues.MODULE_RESULTS[ip],
                result_file,
                indent=4
            )


def search_in_list(document: list) -> dict or None:
    """
    Search recursively in list
    :param document: part of a document
    :return: founded dictionary
    """
    result = {}
    for doc in document:
        if isinstance(doc, list):
            result_doc = search_in_list(doc)
            if result_doc:
                result.update(result_doc)
        if isinstance(doc, dict):
            result_doc = find_values_by_key(doc)
            if result_doc:
                result.update(result_doc)
    if result:
        return result
    else:
        return None


def search_by_key(document: dict, key) -> dict or None:
    """
    Get a dictionary with keys we are interested in
    :param document: dictionary from document
    :param key: key from dict
    :return: dictionary with founded similar keys
    """
    for info in DBScannerDefaultValues.CRITICAL_INFORMATION:
        regular = findall(info + DBScannerDefaultValues.NOT_INCLUDED, key)
        if regular:
            if isinstance(document[key], str):
                if "_id" in document[key]:
                    return None
                else:
                    return {str(key): str(document[key])}
            if isinstance(document[key], int) or isinstance(document[key], float):
                if document[key] == 0:
                    return None
                else:
                    return {str(key): str(document[key])}
            if document[key]:
                return {str(key): str(document[key])}
    return None


def search_by_value(document: dict, key) -> dict or None:
    """
    Take a dictionary with values we are interested in
    :param document: dictionary from document
    :param key: key from dict
    :return: dictionary with founded similar values
    """
    if "_id" in str(document[key]):
        return None
    for info in DBScannerDefaultValues.CRITICAL_INFORMATION_VALUES:
        regular = findall(info, str(document[key]))
        if regular:
            return {str(key): str(document[key])}
    return None


def find_values_by_key(document: dict) -> dict or None:
    """
    Find different possible critical information by set regular expressions
    :param document: document from the database
    :return: found possible critical data
    """
    document_dict = {}
    for key in document.keys():
        if "_id" in key:
            continue
        if not isinstance(document[key], list) and not isinstance(document[key], dict):
            document_value_result = search_by_value(document, key)
            if document_value_result:
                document_dict.update(document_value_result)
                continue
            document_key_result = search_by_key(document, key)
            if document_key_result:
                document_dict.update(document_key_result)
        else:
            if isinstance(document[key], list):
                result_list = search_in_list(document[key])
                if result_list:
                    document_dict.update(result_list)
            else:
                result_list = find_values_by_key(document[key])
                if result_list:
                    document_dict.update(result_list)
    if not document_dict:
        return

    return document_dict


def convert_dict_values_into_needed_type(
    document: dict or list
) -> dict or list or None:
    """
    Miss keys that we are not interested in and save values as str
    :param document: document from database
    :return: changed dictionary
    """
    result_dict = {}
    if isinstance(document, list):
        resulted_list = []
        for doc in document:
            if isinstance(doc, list) or isinstance(doc, dict):
                resulted = convert_dict_values_into_needed_type(doc)
                if resulted:
                    resulted_list.append(resulted)
            else:
                if "_id" in str(doc):
                    continue
                resulted_list.append(str(doc))
        if resulted_list:
            return resulted_list
        else:
            return None
    for key in document.keys():
        if findall(DBScannerDefaultValues.NOT_INCLUDED, key):
            continue
        if isinstance(document[key], dict) or isinstance(document[key], list):
            returned = convert_dict_values_into_needed_type(document[key])
            if returned:
                result_dict.update({key: returned})
        else:
            if "_id" in str(document[key]):
                continue
            result_dict.update({key: str(document[key])})
    return result_dict


# TODO: improve regulars
class MongoDB:
    def __init__(self, ip: str):
        self.ip = ip
        self.port = 27017
        self.server_timeout = 10000  # serverSelectionTimeoutMS
        self.socket_timeout = 300000  # socketTimeoutMS
        self.connection_timeout = 10000  # connectTimeoutMs
        self.start = perf_counter()

    def check_time_of_connection(self) -> None:
        """
        Check time of a connection
        :return: None
        """
        if (
            perf_counter() - self.start
        ) > DBScannerDefaultValues.MAX_TIME_OF_CONNECTION_IN_SECONDS:
            raise DBScannerConnectionTimeout(
                "Connection was over because there are too many documents in db"
            )

    @staticmethod
    def get_collection_names(client: database) -> (list or None, Exception or None):
        """
        Det collection name and catch all errors
        :param client: MongoClient.database
        :return: names of collections or error
        """
        try:
            collection_names = client.list_collection_names()
        except (AutoReconnect, OperationFailure, KeyError, InvalidName) as err:
            print(f"Connection was over by server: {err}")
            return None, err
        return collection_names, None

    @staticmethod
    def get_number_of_documents(
        client: database, collection_name: str
    ) -> int or Exception:
        """
        Get number of documents in a collection
        :param client: MongoClient.database
        :param collection_name: name of a collection in database
        :return: number of documents in a collection or exception
        """
        try:
            docs_num = client[collection_name].count_documents({})
        except (
            AutoReconnect,
            InvalidName,
            OperationFailure,
        ) as err:
            print(f"Connection was over by server: {err}")
            return err
        return docs_num

    def find_in_collection_with_reg(
        self, client: database, collection_name: str
    ) -> (dict or None, Exception or None):
        """
        Find values in collection using regular expressions for searching
        :param client: MongoClient.database
        :param collection_name: name of a collection in database
        :return: founded result
        """
        resulted_value = self.get_number_of_documents(client, collection_name)
        if not isinstance(resulted_value, int):
            return None, resulted_value
        docs_num = resulted_value
        result_list = []
        if not docs_num:
            return None, None
        keys = client[collection_name].find_one().keys()
        keys_to_take = []
        regulars = []
        projection = {}
        for key in keys:
            if findall(DBScannerDefaultValues.NOT_INCLUDED, key):
                projection.update({key: 0})
                continue
            for info in DBScannerDefaultValues.CRITICAL_INFORMATION:
                if findall(info, key):
                    keys_to_take.append(key)
                    break
            if key in keys_to_take:
                continue
            else:
                regs = {
                    key: {
                        "$regex": DBScannerDefaultValues.REGULARS_VALUES
                        + DBScannerDefaultValues.REGULARS_INFO,
                        "$options": "i",
                    }
                }
                regulars.append(regs)
        if keys_to_take:
            key_projection = {}
            for key in keys_to_take:
                key_projection.update({key: 1})
            key_projection.update({"_id": 0})
            result = client[collection_name].find(
                projection=key_projection,
                limit=100,
            )
            for doc in result:
                converted = convert_dict_values_into_needed_type(doc)
                if converted:
                    if converted not in result_list:
                        result_list.append(converted)
            try:
                self.check_time_of_connection()
            except DBScannerConnectionTimeout as err:
                if err:
                    return result_list, err
        result = [
            client[collection_name].find(reg, projection, limit=100) for reg in regulars
        ]
        for cursor in result:
            for doc in cursor:
                res = find_values_by_key(doc)
                if res:
                    if res not in result_list:
                        result_list.append(res)
            try:
                self.check_time_of_connection()
            except DBScannerConnectionTimeout as err:
                if err:
                    return result_list, err
        return result_list, None

    def find_values_in_collection(
        self, client: database, collection_name: str
    ) -> (dict or None, Exception or None):
        """
        Find values in documents taken from database without filtering
        :param client: MongoClient.database
        :param collection_name: name of a collection in database
        :return: founded result
        """
        resulted_value = self.get_number_of_documents(client, collection_name)
        if not isinstance(resulted_value, int):
            return None, resulted_value
        docs_num = resulted_value
        collection_list = []
        if not docs_num:
            return None, None
        cursor = client[collection_name].find(limit=100)
        try:
            for document in cursor:
                document_dict = find_values_by_key(document)
                if document_dict is not None:
                    collection_list.append(document_dict)
        except JSONDecodeError as err:
            print(f"Error occurred with decoding: {err}")
            return None, err
        if collection_list:
            return collection_list, None
        else:
            return None, None

    def search_into_db(self, collection_names: list, client: database) -> (dict, Exception or None):
        """
        Run a search ni one database of host and catch relevant errors
        :param collection_names: name of collections in database
        :param client: MongoClient.databse
        :return: result and exception 
        """
        db_dict = {}
        for collection_name in collection_names:
            if not collection_name:
                continue
            try:
                returned_dict, err = self.find_in_collection_with_reg(
                    client, collection_name
                )
                if returned_dict:
                    db_dict[collection_name] = returned_dict
                if err:
                    if isinstance(err, InvalidName) or isinstance(err, JSONDecodeError):
                        continue
                    else:
                        return db_dict, err
                try:
                    self.check_time_of_connection()
                except DBScannerConnectionTimeout as err:
                    if err:
                        return db_dict, err
            except (NetworkTimeout, CursorNotFound, AutoReconnect, OSError) as err:
                print(f"Waiting of server is too long: {err}")
                return db_dict, err
        return db_dict, None

    def initialize(self) -> Exception or None:
        """
        Connect to host and run a search in MongoDB
        :return: founded result
        """
        with MongoClient(
            self.ip,
            self.port,
            serverSelectionTimeoutMS=self.server_timeout,
            socketTimeoutMS=self.socket_timeout,
            connectTimeoutMs=self.connection_timeout,
        ) as client:
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
                return err
            if db_names is None:
                return
            host_dict = {
                "port": self.port,
                "version": client.server_info()["version"],
                "status": None,
            }
            for db in db_names:
                collection_names, err = self.get_collection_names(client[db])
                if err is AutoReconnect:
                    if extract_tb(1) != ConnectionResetError:
                        continue
                    else:
                        host_dict["status"] = str(err)
                        DBScannerDefaultValues.MODULE_RESULTS.update(
                            {self.ip: host_dict}
                        )
                        return err
                if not collection_names:
                    continue
                result_in_db, err = self.search_into_db(collection_names, client[db])
                if result_in_db:
                    host_dict[db] = result_in_db
                if err:
                    DBScannerDefaultValues.MODULE_RESULTS.update({self.ip: host_dict})
                    host_dict["status"] = str(err)
                    return err
            host_dict["status"] = "success"
            DBScannerDefaultValues.MODULE_RESULTS.update({self.ip: host_dict})
            return None


def main(host_info: dict) -> dict:
    """
    Return critical data or something similar about host if it's possible
    :param host_info: information about host
    :return: dictionary with data
    """
    DBScannerDefaultValues.TEMPORARY_RESULTS_DIRECTORY.mkdir(
        exist_ok=True, parents=True
    )
    try:
        if host_info.get("port") == 27017:
            host_ip = host_info.get("ip")
            mongodb = MongoDB(host_ip)
            err = mongodb.initialize()
            if DBScannerDefaultValues.MODULE_RESULTS:
                if len(list(DBScannerDefaultValues.MODULE_RESULTS[host_ip].keys())) > 3:
                    save_temporary_results()
            if error:
                return {
                    "status": str(err),
                    "host_info": DBScannerDefaultValues.MODULE_RESULTS[host_ip],
                }
            else:
                return {
                    "status": "success",
                    "host_info": DBScannerDefaultValues.MODULE_RESULTS[host_ip],
                }
    except Exception as err:
        return {"error": str(err)}


if __name__ == "__main__":
    DBScannerDefaultValues.TEMPORARY_RESULTS_DIRECTORY.mkdir(
        exist_ok=True, parents=True
    )
    ip_list = load_hosts()
    for ip_value in ip_list:
        print(ip_value)
        md = MongoDB(ip_value)
        error = md.initialize()
        if error:
            print(error)
        else:
            print("Connection ended without errors")
        # save_temporary_results()
        save_results(DBScannerDefaultValues.MODULE_RESULTS)
