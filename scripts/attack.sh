#!/bin/bash

TARGET="http://127.0.0.1:8000/login"

echo "Starting brute force simulation..."

for i in {1..25}
do
  curl -s -X POST -d "username=admin&password=wrongpass" $TARGET > /dev/null
done

echo "Brute force attack completed."