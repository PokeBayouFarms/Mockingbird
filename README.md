# Mockingbird  
Semi-decentralized, asynchronous private messaging.  

## Installation:  
  Run mockingbird_setup.exe, this installs the client and server applications.  
  Server configuration is handled through the server_config.json file, any port can be used.  

## Usage:  

### Client:  
  Run mockingbird_client.exe.  
  Enter a username and password.  
  Scan the QR using your authenticator app of choice. This is technically optional, but you will not be able to use the same key pair in a new session without it.  
  *** If you lose your TOTP/2FA access, you must reinstall Mockingbird! ***  
  Go to the server tab, and enter the hostname/ip and port of your chosen server. If the server is hosted locally, you can just use localhost:(port).  
  To register as a user, press the "Register / Reregister" button. This can also be used to register to other servers as needed.  
  To check the server for available users, press the "Query Registered Users" button. This shows users holding a mailbox on the designated server.  
  Go to the messaging tab, and designate a recipient (you can enter your own username to test), then enter your message, and press send.  
  To check for messages addressed to you, just click Check Mailbox.

### Server:  
  Open your preferred port, and designate this in the server_config.json file included in the install.  
  Run mockingbird_server.exe.  
  Provide the hostname/ip and port information to users as you see fit.
    
## Technical Information:  
  Client side keys are secured via AES-256 with a PBKDF2-derived key from the user password.
