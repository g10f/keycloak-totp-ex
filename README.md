# Keycloak TOTP Provider

Keycloak TOTP provider which base32 decodes TOTP secrets, so that 
secrets from external data sources can be imported into the keycloak 
credential table.


## Installation
copy the jar-file to the deployment dir of keycloak

disable the original totp credential provider

    "credential": {
        "keycloak-otp": {
            "enabled": false
        }
    },


import TOTP secrets

    PUT /auth/realms/{realm}/user/{username}/totp-ex 
    json payload:  {"type": "totp", "device": "ex", "value": "{base32 encoded totp secret}"}
    
When importing TOTP secrets with device != "ex", the default keycloack behaviour is implemented and
all existing TOTP secrets of the user are deleted.
Importing  TOTP secrets with device = "ex", only existing "ex" TOTP secrets are removed.