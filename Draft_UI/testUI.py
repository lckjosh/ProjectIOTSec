from pyfiglet import Figlet
from tqdm import tqdm
import sys

f = Figlet(font='slant')
print(f.renderText('Project IoTSec'))

#print ur menu options
choices = ['scan', 'settings']
prompt = ('Option 1 : scan [default] \n' +
        'Option 2 : settings\n')
        
#wait for user input
user_choice = input(prompt).lower()

while user_choice and user_choice not in choices:
    print('Use with either "scan" or "settings" as input, got it?')
    user_choice = input(prompt).lower()

# Incase user Input was blank, Assign default option
user_choice = choices[0] if not user_choice else user_choice

# Depends on what user input, run/call the corresponding python file
if user_choice != 'scan' :
    print('Settings')
else: 
    print ('Which vulnerable device would you like to exploit? \n ASUS Router \n VeraEdge \n Dlink Camera \n QNAP Nest \n FosCam Camera')

# Loading of individual python scripts for exploiting 