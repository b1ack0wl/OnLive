#!/bin/sh

app=exec_wifi_boot

for app_pid in $(ps -ef | grep $app | grep -v grep | awk '{print $2}'); do
	kill -9 $app_pid
done

