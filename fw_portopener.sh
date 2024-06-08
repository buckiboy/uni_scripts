#!/bin/bash

# List of ports to open
ports=(
    80 161 23 3389 5900 143 110 3306 5432 6379 11211 27017 5672 9200
    9092 2049 587 990 465 636 88 873 162 389 5060 520 69 179 123 49
    1812
)

# Iterate through the list of ports and open each one using ufw
for port in "${ports[@]}"; do
    sudo ufw allow $port
done

# Enable ufw if not already enabled
sudo ufw enable

# Status to confirm the rules
sudo ufw status
