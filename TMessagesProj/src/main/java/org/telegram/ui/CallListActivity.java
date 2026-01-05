/*
 * Call List Activity
 * For managing blacklist, whitelist, and auto-answer contacts
 */

package org.telegram.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;

import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.CallSettingsManager;
import org.telegram.messenger.ContactsController;
import org.telegram.messenger.LocaleController;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.R;
import org.telegram.messenger.UserConfig;
import org.telegram.tgnet.TLRPC;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.Cells.TextCell;
import org.telegram.ui.Cells.TextInfoPrivacyCell;
import org.telegram.ui.Cells.UserCell;
import org.telegram.ui.Components.LayoutHelper;
import org.telegram.ui.Components.RecyclerListView;

import java.util.ArrayList;
import java.util.List;

public class CallListActivity extends BaseFragment {

    public static final int TYPE_BLACKLIST = 0;
    public static final int TYPE_WHITELIST = 1;
    public static final int TYPE_AUTO_ANSWER = 2;

    private int listType;
    private RecyclerListView listView;
    private ListAdapter listAdapter;
    
    private List<Long> userIds = new ArrayList<>();

    // Row indices
    private int rowCount;
    private int addContactRow;
    private int usersStartRow;
    private int usersEndRow;
    private int infoRow;

    public CallListActivity(int type) {
        this.listType = type;
    }

    @Override
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        loadUsers();
        updateRows();
        return true;
    }

    private void loadUsers() {
        userIds.clear();
        CallSettingsManager manager = CallSettingsManager.getInstance();
        switch (listType) {
            case TYPE_BLACKLIST:
                userIds.addAll(manager.getBlacklist());
                break;
            case TYPE_WHITELIST:
                userIds.addAll(manager.getWhitelist());
                break;
            case TYPE_AUTO_ANSWER:
                for (CallSettingsManager.AutoAnswerEntry entry : manager.getAutoAnswerList()) {
                    userIds.add(entry.userId);
                }
                break;
        }
    }

    private void updateRows() {
        rowCount = 0;
        addContactRow = rowCount++;
        
        if (!userIds.isEmpty()) {
            usersStartRow = rowCount;
            rowCount += userIds.size();
            usersEndRow = rowCount;
        } else {
            usersStartRow = -1;
            usersEndRow = -1;
        }
        
        infoRow = rowCount++;
    }

    @Override
    public View createView(Context context) {
        actionBar.setBackButtonImage(R.drawable.ic_ab_back);
        actionBar.setAllowOverlayTitle(true);
        
        String title;
        switch (listType) {
            case TYPE_BLACKLIST:
                title = LocaleController.getString("Blacklist", R.string.Blacklist);
                break;
            case TYPE_WHITELIST:
                title = LocaleController.getString("Whitelist", R.string.Whitelist);
                break;
            case TYPE_AUTO_ANSWER:
                title = LocaleController.getString("AutoAnswer", R.string.AutoAnswer);
                break;
            default:
                title = "";
        }
        actionBar.setTitle(title);
        
        actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() {
            @Override
            public void onItemClick(int id) {
                if (id == -1) {
                    finishFragment();
                }
            }
        });

        fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) fragmentView;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));

        listView = new RecyclerListView(context);
        listView.setLayoutManager(new LinearLayoutManager(context, LinearLayoutManager.VERTICAL, false));
        listView.setVerticalScrollBarEnabled(false);
        frameLayout.addView(listView, LayoutHelper.createFrame(LayoutHelper.MATCH_PARENT, LayoutHelper.MATCH_PARENT));
        listView.setAdapter(listAdapter = new ListAdapter(context));
        listView.setOnItemClickListener((view, position) -> {
            if (position == addContactRow) {
                showContactPicker();
            } else if (position >= usersStartRow && position < usersEndRow) {
                int index = position - usersStartRow;
                if (index >= 0 && index < userIds.size()) {
                    long userId = userIds.get(index);
                    showUserOptions(userId);
                }
            }
        });

        return fragmentView;
    }

    private void showContactPicker() {
        Bundle args = new Bundle();
        args.putBoolean("onlyUsers", true);
        args.putBoolean("returnAsResult", true);
        args.putBoolean("allowSelf", false);
        ContactsActivity contactsActivity = new ContactsActivity(args);
        contactsActivity.setDelegate((user, param, activity) -> {
            if (user != null) {
                addUser(user.id);
                activity.finishFragment();
            }
        });
        presentFragment(contactsActivity);
    }

    private void addUser(long userId) {
        CallSettingsManager manager = CallSettingsManager.getInstance();
        
        switch (listType) {
            case TYPE_BLACKLIST:
                if (!manager.isBlacklisted(userId)) {
                    manager.addToBlacklist(userId);
                }
                break;
            case TYPE_WHITELIST:
                if (!manager.isWhitelisted(userId)) {
                    manager.addToWhitelist(userId);
                }
                break;
            case TYPE_AUTO_ANSWER:
                if (!manager.isAutoAnswer(userId)) {
                    showAutoAnswerModeDialog(userId);
                    return; // Don't refresh yet, wait for dialog
                }
                break;
        }
        
        loadUsers();
        updateRows();
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private void showAutoAnswerModeDialog(long userId) {
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("AutoAnswerMode", R.string.AutoAnswerMode));
        
        String[] items = new String[]{
            LocaleController.getString("AudioCallsOnly", R.string.AudioCallsOnly),
            LocaleController.getString("AudioAndVideoCalls", R.string.AudioAndVideoCalls)
        };
        
        builder.setItems(items, (dialog, which) -> {
            int mode = which == 0 ? CallSettingsManager.AUTO_ANSWER_AUDIO_ONLY : CallSettingsManager.AUTO_ANSWER_AUDIO_VIDEO;
            CallSettingsManager.getInstance().addAutoAnswer(userId, mode);
            loadUsers();
            updateRows();
            if (listAdapter != null) {
                listAdapter.notifyDataSetChanged();
            }
        });
        
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
    }

    private void showUserOptions(long userId) {
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        
        TLRPC.User user = MessagesController.getInstance(currentAccount).getUser(userId);
        String userName = user != null ? ContactsController.formatName(user.first_name, user.last_name) : String.valueOf(userId);
        builder.setTitle(userName);
        
        List<String> items = new ArrayList<>();
        items.add(LocaleController.getString("Delete", R.string.Delete));
        
        if (listType == TYPE_AUTO_ANSWER) {
            items.add(LocaleController.getString("ChangeMode", R.string.ChangeMode));
        }
        
        builder.setItems(items.toArray(new String[0]), (dialog, which) -> {
            if (which == 0) {
                // Delete
                removeUser(userId);
            } else if (which == 1 && listType == TYPE_AUTO_ANSWER) {
                // Change mode
                showAutoAnswerModeDialog(userId);
            }
        });
        
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
    }

    private void removeUser(long userId) {
        CallSettingsManager manager = CallSettingsManager.getInstance();
        
        switch (listType) {
            case TYPE_BLACKLIST:
                manager.removeFromBlacklist(userId);
                break;
            case TYPE_WHITELIST:
                manager.removeFromWhitelist(userId);
                break;
            case TYPE_AUTO_ANSWER:
                manager.removeAutoAnswer(userId);
                break;
        }
        
        loadUsers();
        updateRows();
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private String getInfoText() {
        switch (listType) {
            case TYPE_BLACKLIST:
                return LocaleController.getString("BlacklistInfo", R.string.BlacklistInfo);
            case TYPE_WHITELIST:
                return LocaleController.getString("WhitelistInfo", R.string.WhitelistInfo);
            case TYPE_AUTO_ANSWER:
                return LocaleController.getString("AutoAnswerInfo", R.string.AutoAnswerInfo);
            default:
                return "";
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {

        private Context mContext;

        public ListAdapter(Context context) {
            mContext = context;
        }

        @Override
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int type = holder.getItemViewType();
            return type == 0 || type == 1;
        }

        @Override
        public int getItemCount() {
            return rowCount;
        }

        @Override
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            switch (viewType) {
                case 0: // Add button
                    view = new TextCell(mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 1: // User cell
                    view = new UserCell(mContext, 4, 0, false);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 2: // Info
                default:
                    view = new TextInfoPrivacyCell(mContext);
                    break;
            }
            return new RecyclerListView.Holder(view);
        }

        @Override
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            switch (holder.getItemViewType()) {
                case 0: // Add button
                    TextCell textCell = (TextCell) holder.itemView;
                    textCell.setTextAndIcon(LocaleController.getString("Add", R.string.Add), R.drawable.msg_contact_add, usersStartRow >= 0);
                    textCell.setColors(Theme.key_windowBackgroundWhiteBlueText4, Theme.key_windowBackgroundWhiteBlueText4);
                    break;
                case 1: // User cell
                    UserCell userCell = (UserCell) holder.itemView;
                    int index = position - usersStartRow;
                    if (index >= 0 && index < userIds.size()) {
                        long userId = userIds.get(index);
                        TLRPC.User user = MessagesController.getInstance(currentAccount).getUser(userId);
                        
                        String status = null;
                        if (listType == TYPE_AUTO_ANSWER) {
                            CallSettingsManager.AutoAnswerEntry entry = CallSettingsManager.getInstance().getAutoAnswerEntry(userId);
                            if (entry != null) {
                                status = entry.mode == CallSettingsManager.AUTO_ANSWER_AUDIO_ONLY 
                                    ? LocaleController.getString("AudioCallsOnly", R.string.AudioCallsOnly)
                                    : LocaleController.getString("AudioAndVideoCalls", R.string.AudioAndVideoCalls);
                            }
                        }
                        
                        userCell.setData(user, null, status, 0, index < userIds.size() - 1);
                    }
                    break;
                case 2: // Info
                    TextInfoPrivacyCell infoCell = (TextInfoPrivacyCell) holder.itemView;
                    infoCell.setText(getInfoText());
                    infoCell.setBackgroundDrawable(Theme.getThemedDrawableByKey(mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                    break;
            }
        }

        @Override
        public int getItemViewType(int position) {
            if (position == addContactRow) {
                return 0;
            } else if (position >= usersStartRow && position < usersEndRow) {
                return 1;
            } else {
                return 2;
            }
        }
    }
}

