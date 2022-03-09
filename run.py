from core.bootstrap import bootstrap
from core.environment import environment
from core.ui import ui
from ui.craft import craft
from ui.tsend import tSend
from ui.tsniff import tSniff
import logging

logging.basicConfig(level=logging.DEBUG,
                    format='\n[%(asctime)s] [%(levelname)s] [%(module)s:%(lineno)d]: %(message)s')
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

# What you pass here are classes, not objects.
# The application is object oriented and uses instances all over the place
enabledFeatures = [ui, environment, craft, tSend, tSniff]
bootstrap.loader(enabledFeatures)