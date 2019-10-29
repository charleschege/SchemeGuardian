## SchemeGuardian Changes by Version

### Version 1.2.0
- Add `AuthState` to show the current status of an authentication mechanism
    1. `RandomDefault` shows that an accounts authentication is currently in a default state with a randomly generated authentication mechanism
    2. `ResetTriggered` shows that a user triggered an authentication for reset
    3. `Transparent` shows that an account auth state is in normal state and visible to the user
    4. `ResetInProgress` shows the authentication code for authentication reset has been triggered. for accounts that have to be pre-registered then the user has to set the authentication mechanism there after
    5. `TempLock` shows an account is temporary locked using a `TempLock`

- Add `TempLock` to give a user account a minimal reset time after multiple authentication attempts
    1. Duration(TAI64N) - set after a specified timeframe
    2. RandomToMail - set only after a user/node confirms a random key from email address
    3. RandomToNode - set only after a user/node confirms a random key from a logged in device
    4. RandomToUser - set after another `associated` user authenticates the random key from an authorized device
    5. RandomToMultiUser - set after multiple `associated` users authenticate the random key from their devices
    6. RandomToSuperUser - set only after an `SuperUser` authenticates the random key
    7. RandomToAdmin - set only after an `Admin` authenticates the random key
    8. RandomToSubAdmin - set only after a `SubAdmin` authenticates the random key
    5. RandomToMultiNode - set after multiple `associated` nodes authenticate the random key