# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/).
This project was forked from Electrum v2.7.1 thus the first release is
labeled as 2.7.1. Subsequent releases will follow
[Semantic Versioning](http://semver.org/).

## [Unreleased]
### Added
  * setup.py will install lbryum as a script
  * added functions for lbrynet in commands.py
  * add channel related commands:
    - `getclaimbynameinchannel`
    - `getdefaultcertificate`
    - `getvalueforuri`
    - `getsignaturebyid`
    - `getclaimbyoutpoint`
    - `getclaimssignedby`
    - `getclaimsinchannel`
    - `getclaimbyid`
    - `getnthclaimforname`
    - `getcertificateclaims`
    - `claimcertificate`
    - `updateclaimsignature`
    - `updatecertificate`
    - `cansignwithcertificate`
    * Added new conditional to `init_cmdline` to check if `cmd.name` is `password` in `lbryum`
    * Added new conditional to `init_cmdline` to check if `new_password` has been parsed in `lbryum`
    * Added new conditional to `init_cmdline` to set `new_password` using `prompt_password('New password:')` if it was not provided. in `lbryum`
    * Added `new_password` to `command_options` in `commands.py` (`*N or **new_password`)
    * Added conditional to parser `if cmd.name == 'password:'` in `commands.py`
    * Added new argument to subparser when condition is true `new_password` is set as a optional argument in `commands.py`
    * Added bool `self.decrypted = False;` to `wallet.py`
    * Added `set_is_decrypted` method to `wallet.py`
    * Added `is_decrypted` method to `wallet.py`
    * Added `wait_until_authenticated(self, callback=None)` method to `wallet.py`
    * Added `wait_for_password()` to `wallet.py` within `wait_until_authenticated(self, callback=None)`
    * Added `if not self.is_decrypted()` conditional as so start up pauses if the password is required to continue  


### Changed
  * include claim address in return from getvalueforname
  * change `abandon` to take `claim_id` instead of `txid` and `nout`
  * change default `amount` in update to None, if `amount` is none use the existing claim amount
  * change `update` to determine (and not require) `claim_id`, `txid`, and `nout` from a given `name`
  * change `claim` to not make a second first-claim if a claim for the name already exists in the wallet unless specified
  * add `claim_sequence` and `claim_address` to claim responses
  * by default expect a hex encoded `val` for `claim` and `update`
  * automatically handle claim signing using default certificate (if one has been made) via `claim` and `update` commands
  # add `channel_name' to claim responses for signed claims
  * Fixed scope issue with `new_password` declaration.
  * Fixed PyLint Errors and warnings
  * removed defunct new_password logic from `init_cmdline`
  
### Fixed
  * fix return amounts for claim list commands
  * return supports list for claim queries
  * fix bug verifying the claim value for a new certificate claim
  * fixed update command
  * fix bugs related to get_name_claims() returning supports

## [2.7.12] - 2017-03-10
### Changed
 * Make key names in dictionary outputs more consistent

## [2.7.8] - 2017-02-27
### Fixed
 * Make requests for individual headers after requesting chunks

## [2.7.6] - 2017-02-21
### Changed
 * Improve packaging of data files to support building with pyinstaller

## [2.7.5] - 2017-02-15
### Fixed
 * Fixed user's supports and updates being spendable by other transactions
