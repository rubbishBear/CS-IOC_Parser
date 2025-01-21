# CS-Parse.py
`CS-Parse.py` is a script that was developed to parse large CSVs containing IOCs that have been pulled down from CrowdStrike Falcon Intelligence. The intent was to only pull out the information that would be relevant in a Splunk lookup table (e.g. indicator, actor, and malware family).

`CS-Parse.py` will break up all the IOCs into their own individual CSV list and pull out the relevant fields for the lookup table. It will keep the original copy of the downloaded CSV, create IOC type-specific CSVs, and append and dedup processed IOCs into a new production list that can be uploaded to your choice of SIEM &ndash; Splunk, in my specific case. 

## Folder Structure
The script is ran using Python 3 and expects to have a folder named `Production` located in the root of where the script will be executed. An additional folder is required in the same path with the name of `Incremental`.

The `Incremental` folder will contain each incremental pull of IOCs from CrowdStrike. Each incremental pull of IOCs needs to have its own folder otherwise it'll become hard to keep track of all the IOCs. As of right now, the script only works against CrowdStrike IOCs due to the way the fields are named. 

The `Production` folder contains CSVs for the following list of IOCs:

```Shell
prod_domainioc.csv
prod_emailioc.csv
prod_fileioc.csv
prod_ipioc.csv
prod_fileioc.csv
prod_ja3.csv
prod_md5hashioc.csv
prod_sha1hashioc.csv
prod_sha256hashioc.csv
prod_urlioc.csv
```

If you choose to parse additional IOC typs, you'll need to create the CSV in the `Production` folder and edit the script as necessary. The column headers for the CSVs must be as follows:

`Indicator,IntrusionSet`

## Editing CSVs
If editing needs to be done on the production CSV's from a Windows machine, the line endings must be in Unix format. A quick fix to this is the following: 

1. Open the CSV in Notepad++
2. Select all text
3. Click Edit -> EOL Conversion -> Unix (LF)

Not performing the above steps may cause issues especially reading from the CSVs. Do not try to edit the CSV using Excel as it may try to change the format upon saving.

## Dependencies
Must have the following dependencies/libraries:

```Python
import sys,time
import os.path as path
import dask.dataframe as dd
from datetime import datetime
```

Dask does not come as part of the default Python install. Information on this library can be found at [https://www.dask.org](https://www.dask.org)

Dask can be installed using the pip:
```Shell
python -m pip install "dask[complete]"
```

OR from source using:
```Shell
git clone https://github.com/dask/dask.git
cd dask
python -m pip install .
# install all dependencies with the following
python -m pip install ".[complete]"
```
## Using the script
After all installation and setup has been complete, you can run the script by issuing the following:

```Shell
./CS-Parse.py ./Incremental/path/to/file/<file>.csv
```

The script will present you with feedback similar to the following:

```Shell
./CS-Parse.py ./Incremental/VenomousBear/Venomous_Bear_Nov_2021.csv  
Start time is: 18:02:27
The ingestCSV name is VenomousBear/Venomous_Bear_Nov_2021.csv
The baseFileName is Venomous_Bear_Nov_2021
Your CSV has 8765 lines and 10 columns.
Filling empty values with 'NON_ATTR'
Formatting 'Actors' and 'Malware_Famalies' and creating 'IntrusionSet'
Writing the Production CSV
Writing Venomous_Bear_Nov_2021_md5hashioc_production_updated_20211212.csv
Writing Venomous_Bear_Nov_2021_sha1hashioc_production_updated_20211212.csv
Writing Venomous_Bear_Nov_2021_sha256hashioc_production_updated_20211212.csv
Writing Venomous_Bear_Nov_2021_domainioc_production_updated_20211212.csv
Writing Venomous_Bear_Nov_2021_urlioc_production_updated_20211212.csv
Writing Venomous_Bear_Nov_2021_ipioc_production_updated_20211212.csv
Writing Venomous_Bear_Nov_2021_emailioc_production_updated_20211212.csv
Writing Venomous_Bear_Nov_2021_fileioc_production_updated_20211212.csv
IOCs have completed parsing.
End time is: 18:07:12
Script completed in: 0:04:45
```

Upon execution, the script will parse out all the IOCs based on IOC type and create a seperate CSV based on its type. The script will also append the new IOCs to the production lists and dedup any IOCs. The next step is to upload the production CSV to whichever server (Splunk, SO, or both if desired).

## Features coming soon
- Log file for tracking updates to your production CSV. 
- Ability to parse IOCs from different CTI platforms
- Create the folders for incremental pulls, move file into the new folder
- Creating and seeding the prod csv's
- Option to rename files