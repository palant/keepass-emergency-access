KeePass emergency access
========================

This tool will generate a web page and a set of keys that can be used to gain access to a KeePass database’s contents in case of an emergency. These keys can be distributed to multiple people, e.g. in printed form. Access is only possible if all keys are present.

The web page needs to be uploaded to a web server along with the (encrypted) KeePass database. If the correct keys are entered, it will be able to decrypt the database and display its contents.

Installing and running the tool
-------------------------------

In order to use this tool, you need to install [Node.js](https://nodejs.org/) first. Once this is done, the simplest way to install and run the tool is the following command:

```sh
npx github:palant/keepass-emergency-access
```

*Note*: If this gives you a “not in this registry” error message, you need to [upgrade npm](https://docs.npmjs.com/try-the-latest-stable-version-of-npm) to version 8.16.0 or above.

Alternatively, you can install this tool globally. Typically, this will require administrator privileges:

```sh
npm install -g github:palant/keepass-emergency-access
```

After installing it in this way, you’ll be able to run the `keepass-emergency-access` command line tool.

Command line parameters
-----------------------

Two command line parameters are required:

* `db_file`: path to the KeePass database file (only KXDB4 format is supported)
* `output_file`: path of the HTML file to be written

Additional command line flags allow changing the number of keys from the default (two keys). Also, they allow you to provide an additional key file used to decrypt the KeePass database.

Uploading the web page
----------------------

The generated web page needs to be uploaded to some web server where it can be accessed. Also, the KeePass database should be uploaded to the same directory and with the same file name it had when the page was generated.

If the KeePass database changes afterwards, you can simply replace it on the web server. You don’t need to re-generate either the web page or the keys. This only becomes necessary if you change your database credentials.

The keys
--------

The generated keys look like this:

```
AFQD37A-BJSZ6G5
CCYWH6K-XP8LPZA
SBEVG6L-J5N4MTB
SS2W67A-4NQYVGH
```

Each key encodes 256 bit of binary data, encoded with [Base32](https://en.wikipedia.org/wiki/Base32) to make entering them manually easier. Together, the keys encode the “composite key” which is a hashed version of your database password and key file. In addition, each key contains a CRC16 checksum allowing to detect incorrectly entered keys.

Security considerations
-----------------------

Even when all but one keys are known, no conclusions can be made about the unknown key thanks to [XOR cipher](https://en.wikipedia.org/wiki/XOR_cipher) being used. The only option is trying to guess that key, which is considerably harder than guessing the database password directly.

Someone in possession of all keys *might* be able to revert the hashing and extract the original database password, particularly if no key file is being used. The hashing used by KeePass boils down to applying SHA256 twice. This is comparably easy to reverse, especially for weak passwords.