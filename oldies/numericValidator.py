
class numericValidator(object):
    
    def __init__(self, userInput, minValue = None, maxValue = None, forbidden = None):
        self.inputType = inputType
        self.minValue = minValue
        self.maxValue = maxValue

    def isItAnInteger(self, input, minValue, maxValue):
        try:
            numericInput = int(input)
            if not (minValue <= numericInput <= maxValue):
              raise Exception("Invalid number '%i'. You must enter a number between %i and %i" % (numericInput, minValue, maxValue))
            return numericInput
        except ValueError, error:
            return "Invalid input '%s': Not a number" % input
        except Exception, error:
            return error
    
    def isItANegativeNumber():
        'Checks wheter the numbers are negative or not'

    
    def respectsLimits(self):
        try:
            if not (minValue <= self.numericInput <= maxValue):
                raise Exception("Invalid number '%i'. You must enter a number between %i and %i" % (numericInput, minValue, maxValue))
        except:


    def isItForbidden():
        pass