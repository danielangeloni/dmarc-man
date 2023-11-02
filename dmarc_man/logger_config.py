import logging

logging.basicConfig(
    format="<%(asctime)s> %(levelname)s [%(filename)s:%(lineno)d]: %(message)s", 
    level=logging.INFO,  # This sets the threshold. All messages above INFO will be displayed
    datefmt='%b %d %Y %H:%M:%S'
)

# Create a logger instance
logger = logging.getLogger(__name__)