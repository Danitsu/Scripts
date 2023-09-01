import json
from OTXv2 import OTXv2, IndicatorTypes
from pandas import json_normalize
from datetime import datetime, timedelta
import codecs
import csv
import os
from datetime import date, datetime

# API key
otx = OTXv2("")

# Get today date of script execution
def get_today_date():
    return date.today().strftime("%Y-%m-%d")

# Custom JSON serializer for datetime objects
def json_datetime_serializer(obj):
    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%d %H:%M:%S")
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

# Save data to file
def save_to_file(data):
    today = get_today_date()
    log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'log')) 

    if not os.path.exists(log_dir):
        os.mkdir(log_dir)
    namefile = os.path.join('/log_' + today + '.txt')
    with open(log_dir+namefile, "a") as myfile:
        json.dump(data, myfile, separators=(",", ":"), default=json_datetime_serializer)
        myfile.write('\n')
        #json.dump(data, myfile, indent=4)

# Severity points
def points_severity(author_username, sections_tags, name_pulse, pulse_count, date_created, indicator_type, indicator):
    # 5. Alienvault + malware + http scan 
    # 4. pulse_count + malware + http scan   
    # 3. pulse_count = revision manual
    # 2. No malicioso 
    # 1. Not found
    if author_username.lower() == 'alienvault' and 'malware' and 'http_scans' in sections_tags:
        data = {"severity": '5', "date_created": date_created, "sections_tags":sections_tags ,"author_username":author_username, "name_pulse":name_pulse, "pulse_count":pulse_count, "indicator_type": indicator_type, "indicator": indicator}
        save_to_file(data)
        print(data)
    elif pulse_count >= 2 and 'malware' and 'http_scans' in sections_tags:
        data = {"severity": '4', "date_created": date_created, "sections_tags":sections_tags ,"author_username":author_username, "name_pulse":name_pulse, "pulse_count":pulse_count, "indicator_type": indicator_type, "indicator": indicator}
        save_to_file(data)
        print(data)
    elif pulse_count >= 2:
        data = {"severity": '3', "date_created": date_created, "sections_tags":sections_tags ,"author_username":author_username, "name_pulse":name_pulse, "pulse_count":pulse_count, "indicator_type": indicator_type, "indicator": indicator}
        save_to_file(data)
        print(data)
    elif pulse_count < 2:
        data = {"severity": '2', "date_created": date_created, "sections_tags":sections_tags ,"author_username":author_username, "name_pulse":name_pulse, "pulse_count":pulse_count, "indicator_type": indicator_type, "indicator": indicator}
        save_to_file(data)
        print(data)
    else:
        data = {"severity": '1', "indicator_type": indicator_type, "indicator": indicator}
        save_to_file(data)
        print(data)

def get_dataalienvault(indicator_details,indicator_type, indicator):
    author_username = indicator_details.get('general', {}).get('pulse_info', {}).get('pulses', [{}])[0].get('author', {}).get('username', {})
    name_pulse = indicator_details.get('general', {}).get('pulse_info', {}).get('pulses', [{}])[0].get('name', {})
    sections_tags = indicator_details.get('general', {}).get('sections', {})
    pulse_count = indicator_details.get('general', {}).get('pulse_info', {}).get('count', {})
    date_created = indicator_details.get('general', {}).get('pulse_info', {}).get('pulses', [{}])[0].get('created', {})
    points_severity(author_username, sections_tags, name_pulse, pulse_count, date_created, indicator_type, indicator)

def read_indicators(namefile):    
    indicador = []
    tipo = []
    with open(namefile, 'r', encoding='utf-8-sig') as file_obj:
        csv_obj = csv.reader(file_obj)
        for row in csv_obj:              
            indicador.append(row[1])
            tipo.append(row[0])
    return indicador, tipo

def get_otxindicators(indicator_type, indicator):
    if "domain" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, indicator)
    elif "IPv4" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.IPv4, indicator)
    elif "IPv6" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.IPv6, indicator)
    elif "hostname" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.HOSTNAME, indicator)
    elif "email" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.EMAIL, indicator)
    elif "url" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.URL, indicator)
    elif "uri" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.URI, indicator)
    elif "FileHash-MD5" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, indicator)
    elif "FileHash-SHA1" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA1, indicator)
    elif "FileHash-SHA256" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA256, indicator)
    elif "FileHash-PEHASH" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_PEHASH, indicator)
    elif "FileHash-IMPHASH" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_IMPHASH, indicator)
    elif "CIDR" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.CIDR, indicator)
    elif "FilePath" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.FILE_PATH, indicator)
    elif "Mutex" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.MUTEX, indicator)
    elif "cve" in indicator_type:
        indicator_details = otx.get_indicator_details_full(IndicatorTypes.CVE, indicator)
    else:
        indicator_details = None

    if indicator_details:
        get_dataalienvault(indicator_details,indicator_type, indicator)
    else:
        print(f'Unsupported indicator type: {indicator_type}')
        raise SystemExit

def main():
    namefile = "indicadores.csv"
    tipos, indicadores = read_indicators(namefile)

    for tipo, indicador in zip(tipos, indicadores):
        get_otxindicators(tipo, indicador)

if __name__ == "__main__":
    main()
