#from curses import has_key
import logging
from core.bootstrap import bootstrap
from utils.menuOptValidator import menuOptValidator
from utils.uiUtils import clearConsole

class ui(object):

    def __init__(self):
        self.menu = {}
        self.exitApp = False

    def resourceLoader(self):
        if 'environment' not in bootstrap.resources:
            raise Exception('The OS type is not available')
        self.os = bootstrap.resources['environment']['os']
        if len(bootstrap.uiModules) == 0:
            raise Exception('No UI modules loaded into the application. Closing...')
        i = 1
        for module in bootstrap.uiModules:
            try:
                self.menu[str(i)] = [module(), module.showUIMenu]
                i += 1
            except Exception as err:
                logging.error(f'Failed to load the UI module. Error: {err}')
                logging.info(f'Trying to load the other modules...')
                pass
        if len(self.menu) == 0:
             raise Exception('Failed to load any UI module into the app. Closing...')

    def exitApplication(self):
        self.exitApp = True

    def run(self):
    
        self.menu['9'] = [self.exitApplication, 'Exit application']
        
        while not self.exitApp:      
            
            userChoice = menuOptValidator(text = 'Enter a menu option: ',
                                          menu =  self.menu, 
                                          showMenu = True,
                                          allowEmpty=False,
                                          clearUI = self.os,
                                          title = ('TRAFFIC APP - MAIN MENU', 1))
            if userChoice == '9':
                self.exitApplication()
            else:
                name, resource = self.menu[userChoice][0].launch() #The resources returned by launch() -ing a specific module, will be appended to bootstrap's resources
                bootstrap.resources[name] = resource                 # so other modules can access them

    def launch(self):
        try:
            self.resourceLoader()
            self.run()
            return 0
        except KeyboardInterrupt:
            raise
        except Exception as err:
            logging.critical(err)
            raise

# Core module whose purpose is to: 
# - build the main menu based on the number of UI modules
# - start launching a UI submodule when the user chooses so
# - append the resources returned by the activity of a UI submodule, to the bootstrap.resources
#   so other modules may use them
#
# If this class is not loaded in run.py, the application can not launch.
# However, in absence of this class, there may be custom scripts that may use the resources returned by the other core modules (if I feel like implementing this function or not:) )
