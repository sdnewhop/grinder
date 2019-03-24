#!/usr/bin/env python3

from pycountry_convert import country_alpha2_to_continent_code as code_to_continent
from pycountry_convert import country_name_to_country_alpha2 as country_to_code

from grinder.decorators import exception_handler
from grinder.errors import GrinderContinentsConvertError


class GrinderContinents:
    @staticmethod
    @exception_handler(expected_exception=GrinderContinentsConvertError)
    def convert_continents(unique_countries: dict) -> dict:
        full_names = {
            "AF": "Africa",
            "AN": "Antarctica",
            "AS": "Asia",
            "EU": "Europe",
            "NA": "North America",
            "OC": "Oceania",
            "SA": "South and Central America",
        }

        continents: dict = {}
        for country in unique_countries.keys():
            try:
                cntry_code = country_to_code(country, cn_name_format="default")
                continent_key = code_to_continent(cntry_code)
                continent = full_names.get(continent_key)
            except KeyError:
                continent = country

            if continent not in continents:
                continents[continent] = unique_countries.get(country)
            else:
                continents[continent] += unique_countries.get(country)

        return continents
