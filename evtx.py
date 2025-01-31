import win32evtlog
import win32evtlogutil
import datetime
import time
import json
import xml.etree.ElementTree as ET
import os
import logging
import requests
import asyncio
import socket
import sys
import subprocess
from datetime import timezone
import argparse

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

API_ENDPOINT = "http://localhost:3000/api/logs"
CHAINSAW_ENDPOINT = "http://localhost:3000/api/chainsaw_logs"


def get_base_path():
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        return sys._MEIPASS
    else:
        # Running as script
        return os.path.dirname(os.path.abspath(__file__))

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google's public DNS server
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        logging.error(f"Error getting local IP: {e}")
        return None

def event_type_to_string(event_type):
    types = {
        win32evtlog.EVENTLOG_SUCCESS: 'Success',
        win32evtlog.EVENTLOG_AUDIT_SUCCESS: 'Audit Success',
        win32evtlog.EVENTLOG_AUDIT_FAILURE: 'Audit Failure',
        win32evtlog.EVENTLOG_ERROR_TYPE: 'Error',
        win32evtlog.EVENTLOG_WARNING_TYPE: 'Warning',
        win32evtlog.EVENTLOG_INFORMATION_TYPE: 'Information'
    }
    return types.get(event_type, f'Unknown ({event_type})')

def get_security_logs(start_time):
    logs = []
    try:
        handle = win32evtlog.OpenEventLog(None, 'Security')
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total_events = win32evtlog.GetNumberOfEventLogRecords(handle)
        logging.info(f"Total events in Security log: {total_events}")

        events = win32evtlog.ReadEventLog(handle, flags, 0)
        
        for event in events:
            if event.TimeGenerated > start_time:
                try:
                    data = {
                        'EventID': event.EventID,
                        'TimeGenerated': str(event.TimeGenerated),
                        'SourceName': event.SourceName,
                        'EventType': event_type_to_string(event.EventType),
                        'EventCategory': event.EventCategory,
                        'Message': win32evtlogutil.SafeFormatMessage(event, 'Security')
                    }
                    logs.append(data)
                    logging.debug(f"Processed event: {data['EventID']} from {data['SourceName']}")
                except Exception as e:
                    logging.error(f"Error processing event: {str(e)}")
        
        win32evtlog.CloseEventLog(handle)
    except Exception as e:
        logging.error(f"Error reading Security log: {str(e)}")
    
    logging.info(f"Collected {len(logs)} events from Security log")
    return logs

def save_evtx(log_type, filename):
    try:
        os.system(f'wevtutil epl {log_type} {filename}')
        logging.info(f"Saved EVTX file: {filename}")
    except Exception as e:
        logging.error(f"Error saving EVTX file: {str(e)}")

def analyze_with_chainsaw(evtx_file, start_time, end_time):
    base_path = get_base_path()
    chainsaw_path = os.path.join(base_path, "chainsaw.exe")
    sigma_rules_path = os.path.join(base_path, "needed")
    mappings_path = os.path.join(base_path, "mappings", "sigma-event-logs-all.yml")
    
    output_folder = os.path.join(base_path, "output")
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    output_file = os.path.join(output_folder, f"chainsaw_results_{start_time.strftime('%Y%m%d_%H%M%S')}.json")

    command = [
        chainsaw_path,
        "hunt",
        evtx_file,
        "-s", sigma_rules_path,
        "--mapping", mappings_path,
        "--from", start_time.strftime("%Y-%m-%dT%H:%M:%S"),
        "--to", end_time.strftime("%Y-%m-%dT%H:%M:%S"),
        "--json",
        "--output", output_file
    ]

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            logging.info("Chainsaw analysis completed successfully.")
            logging.info(f"Output file: {output_file}")
            logging.info(f"Command output: {stdout}")
            return output_file
        else:
            logging.error("Chainsaw analysis failed.")
            logging.error(f"Error: {stderr}")
            return None
    except Exception as e:
        logging.error(f"An error occurred during Chainsaw analysis: {str(e)}")
        return None

async def upload_to_api(logs, access_key):
    try:
        # Create XML
        root = ET.Element("Events")
        for log in logs:
            event = ET.SubElement(root, "Event")
            for key, value in log.items():
                ET.SubElement(event, key).text = str(value)
        
        xml_content = ET.tostring(root, encoding='unicode')
        
        # Send to API
        response = requests.post(
            API_ENDPOINT,
            files={
                'xml_file': ('logs.xml', xml_content, 'application/xml'),
            },
            data={
                'accessKey': access_key,
            }
        )
            
        if response.status_code == 200:
            logging.info(f"Uploaded logs to API successfully")
        else:
            logging.error(f"Failed to upload to API. Status code: {response.status_code}")
            logging.error(f"Response: {response.text}")
    except Exception as e:
        logging.error(f"Error uploading to API: {str(e)}")

def upload_chainsaw_results(json_file, access_key, ip_address, desktop_name):
    try:
        with open(json_file, 'r') as f:
            chainsaw_logs = json.load(f)

        if not chainsaw_logs:  # If the JSON file is empty (only [])
            logging.info("Chainsaw results are empty. Skipping upload.")
            return

        files = {'json_file': (os.path.basename(json_file), json.dumps(chainsaw_logs), 'application/json')}
        data = {
            'accessKey': access_key,
            'ipAddress': ip_address,
            'desktopName': desktop_name
        }
        
        response = requests.post(CHAINSAW_ENDPOINT, files=files, data=data)
        
        if response.status_code == 200:
            logging.info(f"Uploaded Chainsaw results to API successfully")
        else:
            logging.error(f"Failed to upload Chainsaw results to API. Status code: {response.status_code}")
            logging.error(f"Response: {response.text}")
    except Exception as e:
        logging.error(f"Error uploading Chainsaw results to API: {str(e)}")

async def main(access_key):
    desktop_name = socket.gethostname()
    local_ip = get_local_ip()

    if not local_ip:
        logging.error("Failed to get local IP address. Exiting.")
        sys.exit(1)

    logging.info(f"Desktop Name: {desktop_name}")
    logging.info(f"Local IP Address: {local_ip}")

    while True:
        start_time = datetime.datetime.now() - datetime.timedelta(minutes=10)
        end_time = datetime.datetime.now()
        
        logging.info(f"Starting log collection for period: {start_time} to {end_time}")
        
        logs = get_security_logs(start_time)
        
        if logs:
            await upload_to_api(logs, access_key)
            
            # Create evtx folder if it doesn't exist
            evtx_folder = os.path.join(get_base_path(), "evtx")
            if not os.path.exists(evtx_folder):
                os.makedirs(evtx_folder)
            
            # Save logs to EVTX
            timestamp = start_time.strftime('%Y%m%d_%H%M%S')
            base_filename = f"Security_{timestamp}"
            evtx_file = os.path.join(evtx_folder, f"{base_filename}.evtx")
            save_evtx('Security', evtx_file)
            
            # Analyze with Chainsaw
            start_time_utc = start_time.astimezone(timezone.utc)
            end_time_utc = end_time.astimezone(timezone.utc)
            chainsaw_output = analyze_with_chainsaw(evtx_file, start_time_utc, end_time_utc)
            if chainsaw_output:
                upload_chainsaw_results(chainsaw_output, access_key, local_ip, desktop_name)
        
        logging.info(f"Log collection cycle completed. Waiting for next cycle.")
        
        # Wait until the next 10-minute mark
        next_run = datetime.datetime.now() + datetime.timedelta(minutes=10)
        next_run = next_run.replace(minute=next_run.minute // 10 * 10, second=0, microsecond=0)
        wait_time = (next_run - datetime.datetime.now()).total_seconds()
        await asyncio.sleep(wait_time)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Windows Log Collector and Chainsaw Analyzer")
    parser.add_argument("-a", "--access-key", required=True, help="Access key for API authentication")
    args = parser.parse_args()

    access_key = args.access_key
    logging.info(f"Logging Access key {access_key}")

    logging.info("Starting Windows Log Collector")
    try:
        asyncio.run(main(access_key))
    except KeyboardInterrupt:
        logging.info("Script terminated by user")
    except Exception as e:
        logging.critical(f"Unexpected error: {str(e)}")

