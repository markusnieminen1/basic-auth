# basic-auth

This project is sub-part of Hive Helsinki curriculum. 

# Idea 

Make the auth flow general enough so that it can also be used in multiple projects. Use interfaces where possible to be able to swap components. (data to extract from requests / DB with CRUD etc. )


## Functionality 

### Registration

Provide API for creating users. Basic user as well as admin. Custom permissions would be then possible making the auth more suitable to use for different use cases.

### Login

Provide endpoint for requesting refresh token and access token. Add generated refresh token into DB. 

### Logout

Remove access token and refresh token from browser memory. Remove refresh token from DB, making it impossible to query new access tokens. 


### Cookie lifecycle management 

Access tokens, Refresh tokens, time validity, SAMESITE:STRICT (making CSFR simple to handle, maybe later add logic for Bearer.) 

### Permission management 

Should have standardised way for managing user permissions. Roles -> Group of permissions.
Granting roles to user will grant xy permissions. User do not need to have role, but can simply have manually added permissions. 

### Logging 

The simple-auth will include logging with basic information. Audit logs, e.g. login success/fail, logout, permission changes, token revocated etc.

Debugging logging.

## Rate limiting 

### Notes 
- Even refresh tokens needs to be hashed. 
- Hashing algorithm for passwords is bcrypt for it's simplicity.
- Hashing algorithm for Refresh tokens is std SHA256.
- Access token (JWT or other signed token) 
- Refresh token per device log in. If password is changed, then revoke all refresh tokens. 

### Asymmetric access/refresh token 

Makes it possible in the future to have services that can sign and create tokens. If the Encryption is symmetric, then ALL devices even verifying the signatures needs the private key. Asymmetric means having public & private keys. Signing devices only needs private keys, verifying devices public key. 

## Use cases  
Middleware -> Extract target headers

Handler -> path validation per user permissions 

Resource -> validation per user permissions

## Tech required 

### Relational database 
- Store user login data such as id, username/email, hashed passwords
- Store user permissions

### Redis cache 
- Fast lookup for refresh token validity 
- Fast lookup for access token blacklist 

Fast lookup could be also achieved using maps. Redis can be used if there's more services at any point. In memory maps would require complex logic to keep the data same on all services.  
