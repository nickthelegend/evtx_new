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

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# HOSTNAME = socket.gethostname()
API_ENDPOINT = "http://localhost:3001/api/logs"

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

async def main(access_key):
    while True:
        start_time = datetime.datetime.now() - datetime.timedelta(minutes=10)
        end_time = datetime.datetime.now()
        
        logging.info(f"Starting log collection for period: {start_time} to {end_time}")
        
        logs = get_security_logs(start_time)
        
        if logs:
            await upload_to_api(logs, access_key)
        
        logging.info(f"Log collection cycle completed. Waiting for next cycle.")
        
        # Wait until the next 10-minute mark
        next_run = datetime.datetime.now() + datetime.timedelta(minutes=10)
        next_run = next_run.replace(minute=next_run.minute // 10 * 10, second=0, microsecond=0)
        wait_time = (next_run - datetime.datetime.now()).total_seconds()
        await asyncio.sleep(wait_time)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python evtx.py <access_key>")
        sys.exit(1)
    
    access_key = sys.argv[1]
    logging.info(f"Logging Access key {access_key}")

    logging.info("Starting Windows Log Collector")
    try:
        asyncio.run(main(access_key))
    except KeyboardInterrupt:
        logging.info("Script terminated by user")
    except Exception as e:
        logging.critical(f"Unexpected error: {str(e)}")

