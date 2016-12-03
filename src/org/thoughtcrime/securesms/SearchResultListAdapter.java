/**
 * Copyright (C) 2011 Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.thoughtcrime.securesms;

import android.content.Context;
import android.database.Cursor;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.app.FragmentActivity;
import android.support.v7.widget.RecyclerView;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnLongClickListener;
import android.view.ViewGroup;

import org.thoughtcrime.redphone.util.Conversions;
import org.thoughtcrime.securesms.crypto.MasterCipher;
import org.thoughtcrime.securesms.crypto.MasterSecret;
import org.thoughtcrime.securesms.database.CursorRecyclerViewAdapter;
import org.thoughtcrime.securesms.database.DatabaseFactory;
import org.thoughtcrime.securesms.database.MmsSmsDatabase;
import org.thoughtcrime.securesms.database.ThreadDatabase;
import org.thoughtcrime.securesms.database.model.ThreadRecord;
import org.thoughtcrime.securesms.database.model.MessageRecord;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * A CursorAdapter for building a list of conversation threads.
 *
 * @author Moxie Marlinspike
 */
public class SearchResultListAdapter extends CursorRecyclerViewAdapter<SearchResultListAdapter.ViewHolder> {

  private final MmsSmsDatabase messageDatabase;
  private final          MasterSecret      masterSecret;
  private final          MasterCipher      masterCipher;
  private final          Locale            locale;
  private final          LayoutInflater    inflater;
  private final          SearchResultClickListener clickListener;
  private final @NonNull MessageDigest     digest;

  private final Set<Long> batchSet  = Collections.synchronizedSet(new HashSet<Long>());
  private       boolean   batchMode = false;



  protected static class ViewHolder extends RecyclerView.ViewHolder {
    public <V extends View & BindableSearchResultListItem> ViewHolder(final @NonNull V itemView)
    {
      super(itemView);
    }

    public BindableSearchResultListItem getItem() {
      return (BindableSearchResultListItem)itemView;
    }
  }

  @Override
  public long getItemId(@NonNull Cursor cursor) {
    MessageRecord record = getMessageRecord(cursor);
    return record.getId();
  }

  public SearchResultListAdapter(@NonNull Context context,
                                 @NonNull MasterSecret masterSecret,
                                 @NonNull Locale locale,
                                 @Nullable Cursor cursor,
                                 @Nullable SearchResultClickListener clickListener)
  {
    super(context, cursor);
    try {
      this.masterSecret   = masterSecret;
      this.masterCipher   = new MasterCipher(masterSecret);
      this.messageDatabase = DatabaseFactory.getMmsSmsDatabase(context);
      this.locale         = locale;
      this.inflater       = LayoutInflater.from(context);
      this.clickListener  = clickListener;
      this.digest         = MessageDigest.getInstance("SHA1");
      setHasStableIds(true);
    } catch (NoSuchAlgorithmException nsae) {
      throw new AssertionError("SHA-1 missing");
    }
  }

  @Override
  public ViewHolder onCreateItemViewHolder(ViewGroup parent, int viewType) {
    Log.i("SearchResultListAdapter", "Creating viewtype " + String.valueOf(viewType));
    final SearchResultListItem item = (SearchResultListItem)inflater.inflate(R.layout.search_result_list_item_view, parent, false);

    item.setOnClickListener(new OnClickListener() {
      @Override
      public void onClick(View view) {
        if (clickListener != null) clickListener.onSearchResultClick(item);
      }
    });

    return new ViewHolder(item);
  }

  @Override
  public void onItemViewRecycled(ViewHolder holder) {
    holder.getItem().unbind();
  }

  @Override
  public void onBindItemViewHolder(ViewHolder viewHolder, @NonNull Cursor cursor) {
    viewHolder.getItem().bind(masterSecret, masterCipher, getMessageRecord(cursor), locale, batchSet, batchMode);
  }

  @Override
  public int getItemViewType(@NonNull Cursor cursor) {
    return 3;
  }

  private MessageRecord getMessageRecord(@NonNull Cursor cursor) {
    return messageDatabase.readerFor(cursor, masterSecret).getCurrent();
  }

  public interface SearchResultClickListener {
    void onSearchResultClick(SearchResultListItem item);
  }
}
