# Searchable Symmetric Encryption for Signal
This report describes our [CS2950][3] project on searchable symmetric encryption for Signal.

## Motivation
Signal does not support search on messages.  We think the reason is that enabling private message search is nontrivial.  So in this work, we leverage the dynamic searchable symmetric encryption (SSE) scheme that is described in [Cash et al][1] and implemented in [Clusion][2], to build the secure search of messages on Signal.

There are several benefits of adding secure search to Signal.  For one, the user can now search over all their messages. Seny's example is that at times he would like to look up his daughter's photo that his wife sent him a while ago on Signal when they were at the park.  On the other hand, the metadata of the messages that are currently unencrypted on Signal (e.g. date and time of the message, sender, sender device, etc.) can now be encrypted and still remain searchable by Signal for different purposes.

Currently, we have implemented the search on messages only.

## Design
At the high level, we implemented an encrypted database (EDB) that serves as an index of the messages stored in Signal's SQLite database.  The index stores a mapping from each word to the message IDs of the messages in which the word appears.  The index is encrypted using symmetric encryption, meaning that both the words and the message IDs are in ciphertext.  This encryption is important because we do not want message plaintexts to be leaked in an in-memory attack.

### Setup
We provide a button in "Settings" -> "Import/Export" -> "Export" -> "Set up EDB" to set up an EDB ([screenshot][setup]).  This will create an EDB for all existing messages on Signal.  This setup only needs to be done once.

### Search
The user can type in the message search keyword at the top of the conversation list ([screenshot][search]).  The matched messages will appear in the same list.  Clicking any of the matched messages will bring the user to the corresponding part of the conversation history.

### New messages
Incoming messages and sent messages will be added to the EDB automatically and become immediately searchable.


## Notes on security
The leakage profile of the SSE scheme includes the total size of the index (i.e. the number of message IDs), the repetition of the search keyword, and the search result (i.e. the matched message IDs).  Our implementation is a dynamic scheme with response hiding and forward security.

The EDB encryption key is generated during the [EDB setup](#setup) and is stored on disk, encrypted with the user's passphrase and MAC address.  The EDB is saved on disk when Signal is locked or closed, and retrieved from disk automatically when Signal is unlocked again.

[1]: internetsociety.org/sites/default/files/07_4_1.pdf
[2]: https://github.com/orochi89/Clusion
[3]: http://cs.brown.edu/~seny/2950-v/
[setup]: https://github.com/zheguang/Signal-Android/blob/master/sse/setup.png
[search]: https://github.com/zheguang/Signal-Android/blob/master/sse/search.png

## Future Work
As noted under [Motivation](#motivation) at the top of this document, we'd like to expand the use of searchable encryption to hide plaintext metadata fields in Signal's SQLite database.  With these fields encrypted, an attacker would not be able to gain important contextual information above messages and conversations.

We would also like to expand the current search function to support some of the metadata fields in Signal's database.  For instance, it would be useful to search by contacts' names.  Another interesting expansion of the search feature would be the automatic tagging of images sent in conversations, enabling users to search for images as well.

## How To Build & Run
1. Download and install Android Studio
2. Clone this repository and open the project in Android Studio
3. Run the project (either in a simulator or on an attached Android device)
4. Navigate to "Settings" -> "Import/Export" -> "Export" and select "Set up EDB"
5. All messages will now be searchable

### Files We Added or Changed
```
build.gradle
res/layout/export_fragment.xml
res/layout/search_result_list_item_view.xml
res/values/strings.xml
src/org/crypto/sse/CryptoPrimitives.java
src/org/crypto/sse/DynRH2Lev.java
src/org/crypto/sse/EdbException.java
src/org/crypto/sse/IEX2Lev.java
src/org/crypto/sse/InvertedIndex.java
src/org/crypto/sse/InvertedIndexResultFormat.java
src/org/crypto/sse/MMGlobal.java
src/org/crypto/sse/RH2Lev.java
src/org/crypto/sse/Record.java
src/org/crypto/sse/TokenDIS.java
src/org/crypto/sse/ZMF.java
src/org/thoughtcrime/securesms/BindableConversationListItem.java
src/org/thoughtcrime/securesms/BindableSearchResultListItem.java
src/org/thoughtcrime/securesms/ConversationActivity.java
src/org/thoughtcrime/securesms/ConversationFragment.java
src/org/thoughtcrime/securesms/ConversationListActivity.java
src/org/thoughtcrime/securesms/ConversationListArchiveActivity.java
src/org/thoughtcrime/securesms/ConversationListFragment.java
src/org/thoughtcrime/securesms/ExportFragment.java
src/org/thoughtcrime/securesms/PassphraseRequiredActionBarActivity.java
src/org/thoughtcrime/securesms/SearchResultListAdapter.java
src/org/thoughtcrime/securesms/SearchResultListItem.java
src/org/thoughtcrime/securesms/crypto/AsymmetricMasterCipher.java
src/org/thoughtcrime/securesms/crypto/MasterSecret.java
src/org/thoughtcrime/securesms/crypto/MasterSecretUtil.java
src/org/thoughtcrime/securesms/database/Edb.java
src/org/thoughtcrime/securesms/database/EdbSecret.java
src/org/thoughtcrime/securesms/database/EncryptingSmsDatabase.java
src/org/thoughtcrime/securesms/database/MmsSmsDatabase.java
src/org/thoughtcrime/securesms/database/SmsDatabase.java
src/org/thoughtcrime/securesms/database/ThreadDatabase.java
src/org/thoughtcrime/securesms/database/loaders/ConversationListLoader.java
src/org/thoughtcrime/securesms/database/loaders/ConversationLoader.java
src/org/thoughtcrime/securesms/util/Util.java
src/org/thoughtcrime/securesms/util/deque/LinkedBlockingDeque.java
sse/README.md
sse/search.png
sse/setup.png
test/unitTest/java/org/crypto/sse/EdbTest.java
test/unitTest/java/org/thoughtcrime/securesms/BaseUnitTest.java
```
The full history of our changes can be found in this repository's commit history.

## Credit
This is a joint work of Tarik Moataz (@orochi89), Sam Zhao (@zheguang), Joe Engelman (@joengelm), and Seny Kamara (@senykam).

## References
* Cash, David, et al. "Dynamic Searchable Encryption in Very-Large Databases: Data Structures and Implementation." IACR Cryptology ePrint Archive 2014 (2014): 853.
