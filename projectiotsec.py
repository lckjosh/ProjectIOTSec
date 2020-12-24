#!/usr/bin/python3

import sys
import os
import exploits
import resources

# print startup screen
os.system('cat resources/banner')

# menu
print("1. Scan Network")
print("2. Help")
print("3. Exit")
choice = input("\nPlease choose option number: ")

if (choice == '1'):
    print("network scan")
elif (choice == '2'):
    print("help")
elif (choice == '3'): 
    print("Exiting...")
    sys.exit(0)
else: 
    print("Invalid choice! Exiting...")
    sys.exit(0)