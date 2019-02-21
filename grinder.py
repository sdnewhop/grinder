#!/usr/bin/env python3

from grinder.asciiart import AsciiOpener
from grinder.core import GrinderCore
from grinder.interface import GrinderInterface

if __name__ == "__main__":
    AsciiOpener.print_opener()
    interface = GrinderInterface()
    interface.check_python_version()
    args = interface.parse_args()
    core = GrinderCore(api_key=args.shodan_key)
    search_results = core.batch_search(queries_file=args.queries_file)

    print(f'Total results: {len(search_results)}')

    core.count_unique_entities('product')
    core.count_unique_entities('vendor')
    core.count_unique_entities('port')
    core.count_unique_entities('proto')
    core.count_unique_entities('country')
    core.count_continents()
    core.update_map_markers(enabled=args.update_markers)
    core.save_results('results')
    core.create_plots()