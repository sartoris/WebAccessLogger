import settings
import psycopg2
import re
from datetime import datetime
from zipfile import ZipFile
import gzip
import os
import ftplib

filelist = []

def check_DataBase_exists():
    conn = psycopg2.connect(
        user=settings.User,
        password=settings.Password,
        host=settings.Host,
        port=settings.Port,
        database="postgres"
    )
    
#     This allows us to execute the CREATE DATABASE statement successfully.
    conn.autocommit = True

    cursor = conn.cursor()
    # Check if the database already exists
    cursor.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (settings.Database,))
    database_exists = cursor.fetchone()

    # If the database does not exist, create it
    if not database_exists:
        cursor.execute(f"CREATE DATABASE {settings.Database}")
        conn.close()
        
        conn = psycopg2.connect(
            user=settings.User,
            password=settings.Password,
            host=settings.Host,
            port=settings.Port,
            database=settings.Database
        )

        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                ip_address VARCHAR(16),
                timestamp timestamp with time zone,
                method TEXT,
                request TEXT,
                version TEXT,
                status_code INT,
                response_size INT,
                referrer TEXT,
                user_agent TEXT )    """)
        
        # TODO: add the 'files' table and perhaps update the 'logs' table script for index and security
        # CREATE TABLE IF NOT EXISTS public.files
        # (
        #     name text COLLATE pg_catalog."default" NOT NULL,
        #     "timestamp" timestamp with time zone NOT NULL DEFAULT now()
        # );

        # CREATE UNIQUE INDEX IF NOT EXISTS pk_files
        #     ON public.files USING btree
        #     (name COLLATE pg_catalog."default" ASC NULLS LAST)
        #     WITH (deduplicate_items=True)
        #     TABLESPACE pg_default;

        # ALTER TABLE IF EXISTS public.files
        #     CLUSTER ON pk_files;

        # ALTER TABLE IF EXISTS public.files
        #     OWNER to dave;

        print(f"The database '{settings.Database}' and Table Logs has been created.")
    else:
        print(f"The database '{settings.Database}' already exists.")

    # Commit the changes and close the connection
    conn.commit()
    cursor.close()
    conn.close()


def process_filename(fileinfo):
    pattern = r'^.*(access_log_\d+.gz)'
    match = re.match(pattern, fileinfo)
    if match:
        filelist.append(match.group(1))


def download_Latest():
    ftp_server = ftplib.FTP(settings.ftpHostName, settings.ftpUserName, settings.ftpPassword)
    ftp_server.encoding = "utf-8"
    ftp_server.cwd("stats")
    ftp_server.retrlines('LIST', process_filename)

    currentdatepattern = "access_log_" + datetime.today().strftime("%Y%m%d") + ".gz"
    for filename in filelist:
        if filename == currentdatepattern: continue # file incomplete
        filepath = os.path.join(settings.localFolder, filename)
        if not os.path.exists(filepath):
            with open(filepath, "wb") as file:
                ftp_server.retrbinary(f"RETR {filename}", file.write)

    ftp_server.quit()

def extract_data(log_line):
    # Define regular expressions to extract relevant information
    pattern = r'^(\S+) - - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+|-) "(.*?)" "(.*?)"'
    match = re.match(pattern, log_line)
    
    if match:
        # Extract individual fields from the log line
        ip_address = match.group(1)
        timestamp = datetime.strptime(match.group(2), "%d/%b/%Y:%H:%M:%S %z")
        method = match.group(3)
        request = match.group(4)
        version = match.group(5)
        status_code = int(match.group(6))
        if match.group(7).isnumeric():
            response_size = int(match.group(7))
        else:
            response_size = 0
        if match.group(8) == "-":
            referrer = ""
        else:
            referrer = match.group(8)
        user_agent = match.group(9)
        
        # Return the extracted data as a dictionary
        return {
            "ip_address": ip_address,
            "timestamp": timestamp,
            "method": method,
            "request": request,
            "version": version,
            "status_code": status_code,
            "response_size": response_size,
            "referrer": referrer,
            "user_agent": user_agent
        }
    else:
        return None

def load_data(data):
    try:
        connection = psycopg2.connect(
            user=settings.User,
            password=settings.Password,
            host=settings.Host,
            port=settings.Port,
            database=settings.Database
        )

        cursor = connection.cursor()
        pg_insert = """INSERT INTO public."logs" 
            ("ip_address", "timestamp", "method", "request", "version", "status_code", "response_size", "referrer", "user_agent")
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        
        Inserted_Values = (data["ip_address"], data["timestamp"], data["method"], data["request"], data["version"], data["status_code"], data["response_size"], data["referrer"], data["user_agent"])

        cursor.execute(pg_insert, Inserted_Values)
        connection.commit()

    except(Exception, psycopg2.Error) as error:
        print("Error connecting to PosgreSQL database", error)
        connection = None

    finally:
        if(connection):
            cursor.close()
            connection.close()

def is_file_parsed(filename):
    try:
        connection = psycopg2.connect(
            user=settings.User,
            password=settings.Password,
            host=settings.Host,
            port=settings.Port,
            database=settings.Database
        )

        exists_query = '''
            select exists (
                select 1
                from files
                where name = %s
            )'''
        cursor = connection.cursor()
        cursor.execute (exists_query, (filename,))
        return cursor.fetchone()[0]

    except(Exception, psycopg2.Error) as error:
        print("Error connecting to PosgreSQL database", error)
        connection = None

    finally:
        if(connection):
            cursor.close()
            connection.close()
            
def save_filename(filename):
    try:
        connection = psycopg2.connect(
            user=settings.User,
            password=settings.Password,
            host=settings.Host,
            port=settings.Port,
            database=settings.Database
        )

        exists_query = '''
            select exists (
                select 1
                from files
                where name = %s
            )'''
        cursor = connection.cursor()
        cursor.execute (exists_query, (filename,))
        exists = cursor.fetchone()[0]

        if not exists:
            insert_query = "insert into files (name) values (%s)"
            cursor.execute (insert_query, (filename,))
            connection.commit()

    except(Exception, psycopg2.Error) as error:
        print("Error connecting to PosgreSQL database", error)
        connection = None

    finally:
        if(connection):
            cursor.close()
            connection.close()


def read_data(filepath):
    data = {}
    robotIps = []
    with gzip.open(filepath, 'rt') as file:
        for line in file:
            dataitem = extract_data(line)
            if dataitem == None: continue
            if dataitem["status_code"] == 404 or dataitem["request"].startswith("/wp-"):
                if robotIps.count(dataitem["ip_address"]) == 0:
                    robotIps.append(dataitem["ip_address"])
                if dataitem["ip_address"] in data:
                    del data[dataitem["ip_address"]]
            else:
                if dataitem["ip_address"] in data:
                    data[dataitem["ip_address"]].append(dataitem)
                else:
                    data[dataitem["ip_address"]] = [dataitem]
    return data

def import_data(filepath):
    try:
        data = read_data(filepath)
        for ip_data in data:
            for dataitem in data[ip_data]:
                load_data(dataitem)
        return True

    except(Exception) as error:
        print(f"Error reading the data from {filepath}", error)
    return False

# check_DataBase_exists()

download_Latest()
for filename in os.listdir(settings.localFolder):
    if filename.startswith('access_log'):
        filepath = os.path.join(settings.localFolder, filename)
        if os.path.isfile(filepath) and not is_file_parsed(filename):
            print(filepath)
            if import_data(filepath):
                save_filename(filename)

