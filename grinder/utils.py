#!/usr/bin/env python3

from collections import Counter


class GrinderUtils:
    def __init__(self):
        self.dict_with_all_results: dict = {}
        self.dict_with_fixed_max_results: dict = {}

    def count_entities(self, results: list, max_entities: int) -> None:
        number_of_entities: dict = Counter(results)
        entities_sorted_by_value = dict(sorted(number_of_entities.items(), key=lambda x: x[1], reverse=True))

        real_max_entities = len(entities_sorted_by_value.keys())
        if max_entities < real_max_entities:
            real_max_entities = max_entities

        # Check if current counted value in dict doesn't have key == None
        self.dict_with_all_results = {key: entities_sorted_by_value[key] for key in list(entities_sorted_by_value) if key is not None}
        self.dict_with_fixed_max_results = {key: entities_sorted_by_value[key] for key in
                                            list(entities_sorted_by_value)[:real_max_entities] if key is not None}

    def get_all_count_results(self) -> dict:
        return self.dict_with_all_results

    def get_fixed_max_count_results(self) -> dict:
        return self.dict_with_fixed_max_results
