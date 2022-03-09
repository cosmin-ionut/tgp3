from utils.uiUtils import clearConsole
from utils.uiUtils import titleFormatter


def menuOptValidator(text, menu, showMenu = False, title = (None, None), allowEmpty = True, clearUI = None):
    uiError = ''
    if title[0]:
        formattedTitle = titleFormatter(title[0], level = title[1])
    while True:
        if clearUI:
            clearConsole(clearUI)
        if title[0]:
            print(formattedTitle)
        if showMenu:
            for k,v in menu.items():
                if isinstance(v, list):
                    print(f'{k}. {v[1]}')
                else:
                    print(f'{k}. {v}')
        print('\n' + uiError)            
        userChoice = input(text)
        if not userChoice and allowEmpty:
            return None
        elif not userChoice and not allowEmpty:
            uiError = 'Invalid option! Try again...'
            continue
        elif userChoice not in menu:
            uiError = 'Invalid option! Try again...'
            continue
        else:
            return userChoice

# Validates the choice of a user, based on the presented options
# - text : shows what is required from the user (Example: Enter a menu option: / Choose an interface:)
# - menu : the menu agains the verifications will be run. The menu has to have the following form:
#          {'option_index', ['what_happe']}
# - showMenu: True|False : display the menu in the UI
# - title : display a title above the menu. (title, titleLevel)
# - allowEmpty : allow Empty input
# - clearUI : clear the ui after choosing an option