General Instructions:

  For running the JS scripts:
    - Install Node.js: https://nodejs.org/en

    - Install the project: npm install

    - Run script: npm <script-name>

  For running Python scripts:
    - Create virtual environment: python -m venv env

    - Activate it: 
      * Mac/Linux: source env/bin/activate
      * Windows: .\env\Scripts\activate

    - Install the requirements.txt: pip install -r requirements.txt


Generating HTML files and dataset:
  - Download one of the files at: https://data.mendeley.com/datasets/c2gw7fy2j4/3

  - Create new "data" directory under the project's directory ("data" should be at the same level of "helpers" for example) 

  - Move pickle files under "data" directory

  - Run the following script from project's main directory:
   python3 ./helpers/export_dataset.py /path/to/project/cyber/data/dataset_name.pickle /path/to/project/cyber/data/phishing_dataset.csv
  
// TODO: 
- Modify script for new data at: https://data.mendeley.com/datasets/n96ncsr5g4/1/files/dac80106-cc68-43c3-8810-96408c09fbbc

