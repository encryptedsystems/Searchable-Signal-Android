# Searchable symmetric encryption of Signal
This report descrbies our [CS2950][3] project on searchable symmetric encryption for Signal.

## Motivation
Signal does not support search on messages.  We think the reason is that enabling private message search is nontrivial.  So in this work, we leverage the dynamic searchable symmetric encryption (SSE) scheme that is described in [Cash et al][1] and implemented in [Clusion][2], to build the secure search of messages on Signal.

There are several benefits of adding secure search to Signal.  For one, the user can now search the messages. Seny's example is that at times he would like to look up his daughter's photo that his wife sent him a while ago on Signal when they were at the park.  On the other hand, the metadata of the messages that are currently unencrypted on Signal, such as date and time of the message, sender, sender device, etc., can now be encrypted and still remain searchable by Signal for different purposes.

Currently, we have implemented the search on messages only.

## Design
At the high level, we implemetned an ecrypted database (EDB) that serves as an index to the messages stored in the SQLite database. The index stores the mapping from each word and the message ids of the messages that it appears in.  The index is encrypted using symmetric encryption, meaning that both the words and the message ids are in ciphertext.  This is important because we do not want to reveal any plaintext of the messages to prevent attacks from memory corruption.

### Setup
We provide a button in "Settings" -> "Import/Export" -> "Export" -> "Set up EDB" to set up an EDB ([screenshot][setup]).  This will create an EDB for any existing messages on Signal.  This setup only needs to be done once.

### Search
The user can type in the message search keyword at the top of the conversation list ([screenshot][search]).  The matched messages will appear in the same list.  Clicking any of the matched messages will bring the user to corresponding part of the conversation history.

### New messages
Incoming messages and sent messages will be added to the EDB automatically, and become immediately searchable.


## Notes on security
The leakage profile of the SSE scheme includes the total size of the index (i.e. the sum of the number of message ids), the reptition of the search keyword, and the search result (i.e. the matched message ids).  Our implementation is a dynamic scheme with response hiding and forward security.

The EDB encryption key is generated during the [EDB setup](#setup) and is stored on disk as encrypted with the user's passphrase and MAC address. The EDB is saved on disk when Signal is locked or closed, and retrieved from disk automatically when Signal is unlocked again.

[1]: internetsociety.org/sites/default/files/07_4_1.pdf
[2]: https://github.com/orochi89/Clusion
[3]: http://cs.brown.edu/~seny/2950-v/
[setup]: https://github.com/zheguang/Signal-Android/blob/master/sse/setup.png
[search]: https://github.com/zheguang/Signal-Android/blob/master/sse/search.png

## Credit
This is a joint work of Tarik Moataz (@orochi89), Sam Zhao (@zheguang), Joe Engelman (@joengelm), and Seny Kamara.

## References
* Cash, David, et al. "Dynamic Searchable Encryption in Very-Large Databases: Data Structures and Implementation." IACR Cryptology ePrint Archive 2014 (2014): 853.
