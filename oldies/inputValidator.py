
#from numericValidator import numericValidator

from interfaceValidator import interfaceValidator
from numericValidator import numericValidator


class inputValidator(numericValidator, interfaceValidator):

    def __init__(self):
        self.validatorDict = {"numeric" : numericValidator(),
                              "interface": interfaceValidator()}

    
    @staticmethod
    def validate(input, *rules):
        
