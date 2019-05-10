#!/usr/bin/env python3
import sys
import os


class ShodanConnectorException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return f"Error occured in Shodan Connector module: {self.error_args}"


class CensysConnectorException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return f"Error occured in Censys Connector module: {self.error_args}"


class NmapConnectorException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return f"Error occured in Nmap Connector module: {self.error_args}"


class NmapProcessingManagerException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return f"Error occured in Nmap Processing Manager module: {self.error_args}"


class GrinderFileManagerException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return f"Error occured in Grinder Filemanager module: {self.error_args}"


class GrinderCoreException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return f"Error occured in Grinder Core module: {self.error_args}"


class GrinderInterfaceException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return f"Error occured in Grinder Interface module: {self.error_args}"


class GrinderContinentsException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return f"Error occured in Grinder Continents module: {self.error_args}"


class GrinderPlotsException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return f"Error occured in Grinder Plots module: {self.error_args}"


class GrinderDatabaseException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return f"Error occured in Grinder Database module: {self.error_args}"


class ShodanConnectorInitError(ShodanConnectorException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class ShodanConnectorSearchError(ShodanConnectorException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class CensysConnectorInitError(CensysConnectorException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class CensysConnectorSearchError(CensysConnectorException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class CensysConnectorGetResultsError(CensysConnectorException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class NmapConnectorInitError(NmapConnectorException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class NmapConnectorScanError(NmapConnectorException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class NmapConnectorGetResultsCountError(NmapConnectorException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class NmapConnectorGetResultsError(NmapConnectorException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class NmapProcessingRunError(NmapProcessingManagerException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class NmapProcessingManagerOrganizeProcessesError(NmapProcessingManagerException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreVulnersScanError(NmapProcessingManagerException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderFileManagerOpenError(GrinderFileManagerException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreSearchError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreBatchSearchError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreProductQueriesError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreHostShodanResultsError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreHostCensysResultsError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreUpdateMapMarkersError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreSaveResultsError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreCountUniqueProductsError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreConvertToContinentsError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreCreatePlotError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreIsHostExistedError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreLoadResultsFromFileError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreLoadResultsFromDbError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreLoadResultsError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreInitDatabaseCallError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreCloseDatabaseError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreUpdateEndTimeDatabaseError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreUpdateResultsCountDatabaseError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreSetCensysMaxResultsError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreAddProductDataToDatabaseError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreShodanSaveToDatabaseError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreCensysSaveToDatabaseError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreSaveResultsToDatabaseError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreNmapScanError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderCoreFilterQueriesError(GrinderCoreException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderInterfaceLoadEnvironmentKeyError(GrinderInterfaceException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderInterfaceParseArgsError(GrinderInterfaceException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderInterfaceGetShodanKeyError(GrinderInterfaceException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderContinentsConvertError(GrinderContinentsException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderPlotsSavePieChartError(GrinderPlotsException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderPlotsAdjustAutopctError(GrinderPlotsException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderPlotsCreatePieChartError(GrinderPlotsException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderDatabaseOpenError(GrinderDatabaseException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderDatabaseCreateError(GrinderDatabaseException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderDatabaseInitialScanError(GrinderDatabaseException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderDatabaseAddScanDataError(GrinderDatabaseException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderDatabaseCloseError(GrinderDatabaseException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderDatabaseUpdateTimeError(GrinderDatabaseException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderDatabaseLoadResultsError(GrinderDatabaseException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderDatabaseUpdateResultsCountError(GrinderDatabaseException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class GrinderDatabaseAddBasicScanDataError(GrinderDatabaseException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)
