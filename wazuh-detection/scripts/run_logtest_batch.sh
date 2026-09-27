#!/bin/bash
echo "Running Wazuh logtest against sample logs..."
for logfile in ../roles/wazuh_detection_engineering/files/tests/*.log; do
    echo "Testing $logfile..."
    cat "$logfile" | /var/ossec/bin/wazuh-logtest
done
