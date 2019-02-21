#!/usr/bin/env python3

class ShodanGathererException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return str(self.error_args)


class GrinderFileManagerException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return str(self.error_args)


class GrinderCoreException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return str(self.error_args)


class GrinderInterfaceException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return str(self.error_args)


class GrinderContinentsException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return str(self.error_args)


class GrinderPlotsException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return str(self.error_args)


class GrinderDatabaseException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return str(self.error_args)


class ShodanGathererInitError(ShodanGathererException):
    def __init__(self, error_args: Exception):
        super().__init__(error_args)


class ShodanGathererSearchError(ShodanGathererException):
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
