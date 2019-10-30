#!/usr/bin/env python3

from pycountry_convert import country_alpha2_to_continent_code as code_to_continent
from pycountry_convert import country_name_to_country_alpha2 as country_to_code

from grinder.decorators import exception_handler
from grinder.errors import GrinderContinentsConvertError


class GrinderContinents:
    @staticmethod
    @exception_handler(expected_exception=GrinderContinentsConvertError)
    def convert_continents(unique_countries: dict) -> dict:
        """
        This function counts the number of continents
        that mapped from unique countries
        :param unique_countries: dictionary with unique countries
        :return: continents with quantity
        """
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
        for country, quantity in unique_countries.items():
            if quantity == 0:
                continue
            try:
                cntry_code = country_to_code(country, cn_name_format="default")
                continent_key = code_to_continent(cntry_code)
                continent = full_names.get(continent_key)
            except KeyError:
                # In this case we know, that our country is not valid.
                # We can check, if it is "Antarctica" somehow,
                # than we will put it as continent. In another case just
                # pass it.
                if country != "Antarctica":
                    continue
                continent = country

            if continent not in continents.keys():
                continents[continent] = quantity
            else:
                continents[continent] += quantity

        continents = dict(
            sorted(continents.items(), key=lambda x: x[1], reverse=True)
        )
        return continents
