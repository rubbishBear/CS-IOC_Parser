#! /usr/bin/env python3
# Author: rubbishBear

import sys,time
import os.path as path
import dask.dataframe as dd
from datetime import datetime

sTime = datetime.now()
print("Start time is: " + sTime.strftime("%H:%M:%S"))
ingestCSV = sys.argv[1]
baseFileName = path.splitext(path.basename(ingestCSV))[0]
print("The ingestCSV name is " + ingestCSV)
print("The baseFileName is " + baseFileName)

# Intitiating dictionary for IOC types
typeDict = {'domain' : 'domainioc',
    'email_address' : 'emailioc',
    'file_name' : 'fileioc',
    'ip_address' : 'ipioc',
    'hash_md5' : 'md5hashioc',
    'hash_sha1' : 'sha1hashioc',
    'hash_sha256' : 'sha256hashioc',
    'url' : 'urlioc'}

# List of desired column headers
newColumnHeaders = ['Indicator',
    'Type',
    'Malware_Families',
    'Actors',
    'Reports',
    'Kill_Chains',
    'Published_Date',
    'Last_Updated',
    'Malicious_Confidence',
    'Labels']

# Read in the new IOC CSV that was passed as arg[0] upon executing the script, also renames the columns with new column headers from the list above
ddf = dd.read_csv(ingestCSV, encoding = 'UTF8', dtype = {'reports':'object','actors':'object','kill_chains':'object'})
ddf = ddf.rename(columns = dict(zip(ddf.columns, newColumnHeaders)))

print("Your CSV has " + str(ddf.shape[0].compute()) + " lines and " + str(ddf.shape[1]) + " columns." )

# Data massaging: filling empty cells with NAN values, if not the script may throw errors or data won't be parsed properly by Dask
print("Filling empty values with \'NON_ATTR\'")
nanReplace = {'Actors':'NON_ATTR','Malware_Families':'GENERIC_MALWARE'}
ddf = ddf.fillna(value = nanReplace)

# Funciton to replace commas with '_' to prevent issues with formatting for CSV
def removeReplaceComma(toJoin):
    toJoin = toJoin.replace(' ','').split(',')
    joined = '_'.join(toJoin)
    return joined

# Data normalization and formatting for CSV
print("Formatting \'Actors\' and \'Malware_Famalies\' and creating \'IntrusionSet\'")
ddf['Actors'] = ddf['Actors'].apply(removeReplaceComma, meta = ('actors','object'))
ddf['Malware_Families'] = ddf['Malware_Families'].apply(removeReplaceComma, meta = ('Malware_Families','object'))
ddf['IntrusionSet'] = ddf['Actors'] + '(' + ddf['Malware_Families'] + ')'

# Creating the new production csv DDF
print("Writing the Production CSV")
ddf = ddf[['Indicator',
    'IntrusionSet',
    'Type',
    'Malware_Families',
    'Actors',
    'Reports',
    'Kill_Chains',
    'Published_Date',
    'Last_Updated',
    'Malicious_Confidence',
    'Labels']]

#Writes a new production CSV of the original incremental pull from CS. This new prodcution CSV includes the newly formatted columns
ddf.to_csv(path.splitext(ingestCSV)[0] + '_prod.csv', single_file = True, encoding = 'UTF8', index = False)

# Seperating out the different IOC types into their own CSV and appending to the production CSV for that IOC type
availableTypes = ddf['Type'].unique()
ddf = ddf.set_index('Type',sorted=True)
for iType in availableTypes:
    if iType in typeDict:
        iTypeCSVBaseName = baseFileName + '_' + typeDict[iType] + '_production_updated_' + datetime.now().strftime("%Y%m%d") + '.csv' 
        iTypeCSVPathName = path.splitext(ingestCSV)[0] + '_' + typeDict[iType] + '_production_updated_' + datetime.now().strftime("%Y%m%d") + '.csv'
        prodCSVName = 'Production/prod_' + typeDict[iType] + '.csv'
        print('Writing ' + iTypeCSVBaseName)
        subsetDDF = ddf.loc[[iType],['Indicator','IntrusionSet']]
        subsetDDF.to_csv(iTypeCSVPathName, single_file = True, encoding = 'UTF8', index = False)
        prodDDF = dd.read_csv(prodCSVName, encoding = 'UTF8')
        combinedDDF = dd.concat([subsetDDF,prodDDF], ignore_unknown_divisions = True)
        # Drop duplicate IOCs from the prodCSV/DDF based on the IOC itself
        combinedUniqueDDF = combinedDDF.drop_duplicates(subset='Indicator')
        combinedUniqueDDF.to_csv(prodCSVName, single_file = True, encoding = 'UTF8', index = False)
        time.sleep(1)

print("IOCs have completed parsing.")
eTime = datetime.now()
print("End time is: " + eTime.strftime("%H:%M:%S"))
delta = eTime - sTime
print("Script completed in: " + str(delta).split('.')[0])