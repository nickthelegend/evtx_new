import win32evtlog
import win32evtlogutil
import win32security
import winerror
import datetime
import time
import json
import xml.etree.ElementTree as ET
import os
import logging

# Set up logging
# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

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

def get_logs(log_type, start_time):
    logs = []
    try:
        handle = win32evtlog.OpenEventLog(None, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total_events = win32evtlog.GetNumberOfEventLogRecords(handle)
        logging.info(f"Total events in {log_type} log: {total_events}")

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
                        'Message': win32evtlogutil.SafeFormatMessage(event, log_type)
                    }
                    logs.append(data)
                    logging.debug(f"Processed event: {data['EventID']} from {data['SourceName']}")
                except Exception as e:
                    logging.error(f"Error processing event: {str(e)}")
        
        win32evtlog.CloseEventLog(handle)
    except Exception as e:
        logging.error(f"Error reading {log_type} log: {str(e)}")
    
    logging.info(f"Collected {len(logs)} events from {log_type} log")
    return logs

def export_to_json(logs, filename):
    try:
        os.makedirs('json', exist_ok=True)
        full_path = os.path.join('json', filename)
        with open(full_path, 'w') as f:
            json.dump(logs, f, indent=4)
        logging.info(f"Exported {len(logs)} events to JSON: {full_path}")
    except Exception as e:
        logging.error(f"Error exporting to JSON: {str(e)}")

def export_to_xml(logs, filename):
    try:
        os.makedirs('xml', exist_ok=True)
        full_path = os.path.join('xml', filename)
        root = ET.Element("Events")
        for log in logs:
            event = ET.SubElement(root, "Event")
            for key, value in log.items():
                ET.SubElement(event, key).text = str(value)
        
        tree = ET.ElementTree(root)
        tree.write(full_path)
        logging.info(f"Exported {len(logs)} events to XML: {full_path}")
    except Exception as e:
        logging.error(f"Error exporting to XML: {str(e)}")

def export_to_evtx(log_type):
    try:
        os.makedirs('evtx', exist_ok=True)
        filename = f"{log_type}.evtx"
        full_path = os.path.join('evtx', filename)
        
        command = f'wevtutil epl "{log_type}" "{full_path}"'
        result = os.system(command)
        
        if result == 0:
            logging.info(f"Exported full EVTX for {log_type}: {full_path}")
        else:
            logging.error(f"Failed to export EVTX for {log_type}. Command exit code: {result}")
    except Exception as e:
        logging.error(f"Error exporting to EVTX: {str(e)}")

def main():
    log_types = ['System', 'Security', 'Application']
    
    while True:
        start_time = datetime.datetime.now() - datetime.timedelta(minutes=10)
        end_time = datetime.datetime.now()
        
        logging.info(f"Starting log collection for period: {start_time} to {end_time}")
        
        for log_type in log_types:
            logging.info(f"Processing {log_type} logs")
            logs = get_logs(log_type, start_time)
            
            if logs:
                timestamp = end_time.strftime("%Y%m%d_%H%M%S")
                base_filename = f"{log_type}_{timestamp}"
                
                export_to_json(logs, f"{base_filename}.json")
                export_to_xml(logs, f"{base_filename}.xml")
                export_to_evtx(log_type)  # Export full EVTX without timestamp
            else:
                logging.warning(f"No logs collected for {log_type}")
        
        logging.info(f"Log collection cycle completed. Waiting for next cycle.")
        
        # Wait until the next 10-minute mark
        next_run = datetime.datetime.now() + datetime.timedelta(minutes=10)
        next_run = next_run.replace(minute=next_run.minute // 10 * 10, second=0, microsecond=0)
        wait_time = (next_run - datetime.datetime.now()).total_seconds()
        time.sleep(wait_time)

if __name__ == "__main__":
    logging.info("Starting Windows Log Collector")
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Script terminated by user")
    except Exception as e:
        logging.critical(f"Unexpected error: {str(e)}")

