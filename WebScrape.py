# Summer 2024
# Data Scraping, Storage, and Visualization


import requests
import html5lib
from bs4 import BeautifulSoup
import OutputUtil as ou


# [2] Define a function to print the HTML content of a webpage at a given URL (uniform resource locator, web address)
def print_html_content(URL):
    r = requests.get(URL)
    print(r.content)


# [3] Define a function to parse the HTML content for a given URL.
def prettify_html_content(URL):
    r = requests.get(URL)
    soup = BeautifulSoup(r.content, 'html5lib')
    print(soup.prettify())


# [4] Define a function to get the next text item from an iterator
def next_text(itr):
    return next(itr).text


# [5] Define a function to get the next int item from an iterator
def next_int(itr):
    return int(next_text(itr).replace(',', ''))


# [6] Define a function to scrape the site.
def get_covid_data(dict_country_population):
    url = 'https://www.worldometers.info/coronavirus/countries-where-coronavirus-has-spread/'
    # get URL html
    page = requests.get(url)
    soup = BeautifulSoup(page.text, 'html.parser')
    data = []
    soup.find_all('td') # will scrape every table-data element in the url's table
    itr = iter(soup.find_all('td'))
    # This loop will keep repeating as long as there is data available in the iterator
    while True:
        try:
            country = next_text(itr)
            if country.startswith('Japan'):
                country = 'Japan'
            cases = next_int(itr)
            deaths = next_int(itr)
            continent = next_text(itr)
            if country in dict_country_population:
                population = dict_country_population[country]
                cases_per_capita = round(100 * cases/population, 2)
                death_rate = round(100 * deaths/cases, 2)
                data.append((country, continent, population, cases, deaths, cases_per_capita, death_rate))
            else:
                print(country, " is missing")
        # StopIteration error is raised when there are no more elements left for iteration
        except StopIteration:
            break
    return data

# Sort the data by the number of confirmed cases
# data.sort(key=lambda row: row[1], reverse=True)


# [7] Define a function get_country_population(url) that will scrape this website to get country populations:
# https://www.worldometers.info/world-population/population-by-country/. Build a dictionary in which the keys
# are country names and the values are country populations.
def get_country_population():
    dict_country_population = {}
    url = 'https://www.worldometers.info/world-population/population-by-country/'
    page = requests.get(url)
    soup = BeautifulSoup(page.text, 'html.parser')
    data = []
    soup.find_all('td') # will scrape every table-data element in the url's table
    itr = iter(soup.find_all('td'))
    # This loop will keep repeating as long as there is data available in the iterator
    while True:
        try:
            junk = next_text(itr)
            country = next_text(itr)
            population = next_int(itr)
            junk = next_text(itr)
            junk = next_text(itr)
            junk = next_text(itr)
            junk = next_text(itr)
            junk = next_text(itr)
            junk = next_text(itr)
            junk = next_text(itr)
            junk = next_text(itr)
            junk = next_text(itr)
            dict_country_population[country] = population
        except StopIteration:
            break
    return dict_country_population


def main():
    url = 'https://www.worldometers.info/coronavirus/countries-where-coronavirus-has-spread/'
    # print_html_content(url)
    # prettify_html_content(url)
    dict_country_population = get_country_population()
    data = get_covid_data(dict_country_population)
    headers = ['Country', 'Continent', 'Population', 'Cases', 'Deaths', 'Cases Per Capita', 'Death Rate']
    types = ['S', 'S', 'N', 'N', 'N', 'N', 'N']
    alignments = ['l', 'l', 'r', 'r', 'r', 'r', 'r']
    title = 'Scraped Covid Data'
    ou.write_html_file('Assignment4.html', title, headers, types, alignments, data, True)
    ou.write_xml_file('Assignment4.xml', title, headers, data, True)
    ou.write_tt_file('Assignment4.txt', title, headers, data, alignments)
    ou.write_csv_file('Assignment4.csv', headers, data)


if __name__ == "__main__":
    main()
