# Securing Social Media Applications
This document is a high-level description of my secure social media application.

The application is based around a messaging board system, with boards that members can send messages to. Users can access the site without logging in, however they will only be able to read messages from the default board. There is a default board to which every user can send a message and read all messages. If users login, they have the option to create their own board, of which they have more control: they can add any registered member of the site, and remove members from the board. For any user-created boards, only those users which are members of the board can view the messages, to all other users the messages appear encrypted.

## Technology used
This is a python application built using flask. It uses flask HTML templates and CSS for the frontend. 

## Authentication
### JSON web tokens
Authentication of whether users of the site are logged in or not is done using JSON web tokens. The python library `flask_jwt_extended` was used to manage this. Once a user logs in they are assigned access and refresh tokens. This allows for refreshing of tokens if they expire.
### Storing user passwords
User passwords are salted, then iteratively hashed using the `sha3_512` algorithm, the has and the salt used are then stored in order to validate passwords.
### Key Management Infrastructure
In this application each board is a group of users. As such, upon creating a new board, a key is assigned to the board, the key being a random 32-byte string. Users are then required to have this key to access the board. The user who created the board is automatically assigned the key.
### Group Membership (Join & Leave)
Anytime users are added to a board they are assigned the key of that board. When a user is removed from the board the key is revoked from them. This is all done on the server, the key is added to the relevant information stored on the user. This means that for every user a unique user identification number, email, password and a list of all the board keys they have access to is stored. When a user is removed from a board, the key of that board is removed from their list of board keys.
### Encryption/Decryption of messages
Messages are encrypted using the `Cryptography.fernet` library. This is an implementation of symmetric authenticated encryption. A 32-byte key is generated upon the application starting, and this key is then used to encrypt and decrypt all messages. When messages are added to any board, they are encrypted upon being recieved by the server, and stored in encrypted form. They are then decrypted if and when necessary to display to users.
### HTTP/HTTPS
The application is currently served over HTTP. This is due to an issue with re-directs to HTTPS not being handled by the default flask server. This could be solved by deploying the application somewhere such as Heroku. This is an issue, as currently user messages and passwords are being sent in plaintext to the server, where they are encrypted. 
### Database
Due to time constraints when building the application a relational database was not implemented. As a temporary measure all information which would be stored in a database is stored in the application memory. 

## Video demonstration
A video demonstration of the use of the application can be found here: https://youtu.be/FIf96UQX24M