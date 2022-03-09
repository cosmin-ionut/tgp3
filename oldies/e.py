import logging
#logging.basicConfig(level=logging.DEBUG) #schimba nivelul de logs si seteaza un logfile
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s:%(levelname)s:%(module)s:%(message)s')
#logging.info() # logheaza un mesaj cu severitate info

#logger = logging.getLogger(__name__)

class helloMeBoyz(object):
    pass


a = helloMeBoyz()

logging.info('hello')