# Searchable Signal (Android) 


## Overview 
Signal is an end-to-end encrypted messaging app made by [Open Whisper
Systems](https://whispersystems.org). It is based on the Signal protocol which
was designed by Trevor Perrin and Moxie Marlinspike.  In addition to underlying
the Signal App, the Signal protocol is also used by WhatsApp, Facebook
Messenger and Google Allo. 


## What This Project is About
We set out to explore whether encrypted search algorithms
could be used to add search functionality to the Signal messaging app without
compromising securely or efficiency.  See this
[writeup](http://esl.cs.brown.edu/post/signal.html) for details on the approach
we took.  


## Disclaimer
We stress that this is a **research project** and that this version of Signal
**should not be used in practice**.  This is not the official version of Signal
produced by Open Whisper Systems. The code has not been reviewed and is only
made available for experimentation and research purposes. **PLEASE DO NOT USE THIS!** 

## How To Build & Run

1. Download and install Android Studio
2. Clone this repository and open the project in Android Studio
3. Run the project (either in a simulator or on an attached Android device)
4. Navigate to "Settings" -> "Import/Export" -> "Export" and select "Set up EDB"
5. All messages will now be searchable

## Files Added or Changed

build.gradle  
gradle/wrapper/gradle-wrapper.properties  
libs/clusion-android-1.0.jar  
res/layout/export_fragment.xml  
res/layout/search_result_list_item_view.xml  
res/values/strings.xml  
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
src/org/thoughtcrime/securesms/database/EdbException.java  
src/org/thoughtcrime/securesms/database/EdbSecret.java  
src/org/thoughtcrime/securesms/database/EncryptingSmsDatabase.java  
src/org/thoughtcrime/securesms/database/MmsSmsDatabase.java  
src/org/thoughtcrime/securesms/database/SmsDatabase.java  
src/org/thoughtcrime/securesms/database/ThreadDatabase.java  
src/org/thoughtcrime/securesms/database/loaders/ConversationListLoader.java  
src/org/thoughtcrime/securesms/database/loaders/ConversationLoader.java  
src/org/thoughtcrime/securesms/util/Util.java  
src/org/thoughtcrime/securesms/util/deque/LinkedBlockingDeque.java  
test/unitTest/java/org/thoughtcrime/securesms/BaseUnitTest.java  


The full history of our changes can be found in this repository's commit history.


## Credit
This is a project from the [Encrypted Systems Lab](http://esl.cs.brown.edu) @
Brown University.  The underlying encrypted search algorithms are provided by
the [Clusion](https://github.com/encryptedsystems/Clusion) library. The project
was led by Joe Engelman (@joengelm) and Sam Zhao (@zhegu) in collaboration
with Tarik Moataz (@orochi89) and Seny Kamara (@senykam).
