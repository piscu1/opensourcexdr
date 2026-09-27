#!/bin/bash
cat /var/ossec/logs/alerts/alerts.json | grep -i "suricata" | tail -n 10 > suricata_samples.json
echo "Samples exported to suricata_samples.json"
