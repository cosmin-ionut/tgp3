import logging
class bootstrap(object):

    resources = {} # resources returned by various modules. This is the central point from where resources will be fetched by any module.
    uiModules = [] # user interface modules. Will be fetched later by UI core.
    coreModules = [] # core modules
     
# the modules enabled will be separated and appended to a list. Core modules will be executed by bootstrap execute() while
# UI modules will not. The core module UI will fetch them at execution and will deal with them.
    @staticmethod
    def loader(enabledFeatures):
        for featureToLoad in enabledFeatures:
            if hasattr(featureToLoad, 'hasUI'):
                bootstrap.uiModules.append(featureToLoad)
            else:
                bootstrap.coreModules.append(featureToLoad)
        bootstrap.execute()
    
    # executes core modules.
    # UI core gets a sepcial treatment
    @classmethod
    def execute(cls):
        try:
            for coreMod in cls.coreModules:
                if coreMod().__class__.__name__ == 'ui':
                    ui = coreMod()
                    continue
                name, resource = coreMod().launch()
                cls.resources[name] = resource
            return ui.launch()  
        except KeyboardInterrupt:
            logging.info('The application has been closed at user\'s request')
            exit(1)
        except Exception as err:
            logging.critical(f'Application cannot continue: {err}')
            exit(1)
                
# Flow:
# all enabled features in run.py will be sent her. They will be sorted into uiModules and coreModules.
# coreModules will be executed here (UI core too) while uiModules will be retrieved by UI core and executed.
