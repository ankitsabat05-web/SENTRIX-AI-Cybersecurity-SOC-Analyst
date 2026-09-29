import os 
from dotenv import load_dotenv

#------------------------------------------
# Load Environment Variables
#------------------------------------------

load_dotenv()

#------------------------------------------
# Application Configuration
#------------------------------------------

APP_NAME = os.getenv(
    "APP_NAME",
    "AI Cybersecurity SOC Analyst"
)

APP_VERSION = os.getenv(
    "APP_VERSION",
    "1.0.0"
)

APP_ENVIRONMENT = os.getenv(
    "APP_ENVIRONMENT",
    "development"
)

APP_DEBUG = os.getenv(
    "APP_DEBUG",
    "True"
).lower() == "true"

#-------------------------------------------
# API Configuration
#-------------------------------------------

API_PREFIX = os.getenv(
    "API_PREFIX",
    "/api/v1"
)

#-------------------------------------------
#Database Configuration
#-------------------------------------------

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlitte:///./soc_analyst.db"
)

#-------------------------------------------
# AI Model Configuration
#-------------------------------------------

AI_MODEL_NAME = os.getenv(
    "AI_MODELNAME",
    "gpt-4"
)

AI_TEMPERATURE = float(
    os.getenv(
        "AI_TEMPERATURE",
        "0.3"  
    )
)

#-------------------------------------------
# Security Configuration 
#-------------------------------------------

SECURITY_KEY = os.getenv(
    "SECRET_KEY",
    "change_this_secret_key_in_production"
)

ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv(
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        "30"
    )
)

#-------------------------------------------
# Logging Configuration
#-------------------------------------------

LOG_LEVEL = os.getenv(
    "LOG_LEVEL",
    "INFO"
)
