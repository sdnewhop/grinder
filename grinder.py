#!/usr/bin/env python3

import sys

from grinder.asciiart import AsciiOpener
from grinder.core import GrinderCore
from grinder.errors import GrinderCoreBatchSearchError, GrinderCoreLoadResultsError
from grinder.interface import GrinderInterface

if __name__ == "__main__":
    AsciiOpener.print_opener()
    interface = GrinderInterface()
    interface.check_python_version()
    args = interface.parse_args()

    core = GrinderCore(shodan_api_key=args.shodan_key,
                       censys_api_id=args.censys_id,
                       censys_api_secret=args.censys_secret)

    if args.censys_max:
        core.set_censys_max_results(args.censys_max)

    try:
        search_results = core.batch_search(queries_filename=args.queries_file) if args.run else core.load_results()
    except (GrinderCoreBatchSearchError, GrinderCoreLoadResultsError):
        print('Unexpected error occured at batch search method.')
        sys.exit(1)

    print(f'Total results: {len(search_results)}')

    if args.count_unique:
        core.count_unique_entities('product')
        core.count_unique_entities('vendor')
        core.count_unique_entities('port')
        core.count_unique_entities('proto')
        core.count_unique_entities('country')
        core.count_continents()
    if args.update_markers:
        core.update_map_markers()
    if args.create_plots:
        core.create_plots()
    if (args.nmap_scan and args.run):
        core.nmap_scan(arguments='-Pn', ports='22,80,443')
    if args.run:
        core.save_results_to_database()
    core.save_results()