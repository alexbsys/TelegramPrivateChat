/*
 * Hidden Chats Activity for Telegram-Xalexb
 * Manages hidden chats: add, remove, change password
 * 
 * In decoy mode, this screen behaves as if it's the real screen,
 * but actually operates on the decoy list.
 */

package org.telegram.ui;

import android.content.Context;
import android.os.Bundle;
import android.text.InputType;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;

import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.DialogObject;
import org.telegram.messenger.EncryptedMessagesManager;
import org.telegram.messenger.HiddenChatsManager;
import org.telegram.messenger.LocaleController;
import org.telegram.messenger.R;
import org.telegram.tgnet.TLRPC;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.Cells.HeaderCell;
import org.telegram.ui.Cells.TextCell;
import org.telegram.ui.Cells.TextInfoPrivacyCell;
import org.telegram.ui.Components.EditTextBoldCursor;
import org.telegram.ui.Components.LayoutHelper;
import org.telegram.ui.Components.RecyclerListView;

import java.util.ArrayList;
import java.util.Set;

public class HiddenChatsActivity extends BaseFragment {

    private RecyclerListView listView;
    private ListAdapter listAdapter;

    private int rowCount;
    private int hideChatsRow;
    private int unhideChatsRow;
    private int changePasswordRow;
    private int decoyPasswordRow;
    private int forgetPasswordRow;
    private int askPasswordOnStartRow;
    private int duplicateDetectionRow;
    private int sectionRow;
    
    // Encrypted calls section
    private int encryptedCallsHeaderRow;
    private int outgoingCallPasswordRow;
    private int incomingCallsHeaderRow;
    private int incomingKeysStartRow;
    private int incomingKeysEndRow;
    private int addIncomingKeyRow;
    private int encryptedCallsInfoRow;
    
    private int hiddenChatsHeaderRow;
    private int hiddenChatsStartRow;
    private int hiddenChatsEndRow;
    private int hiddenChatsInfoRow;

    private ArrayList<Long> hiddenChatsList = new ArrayList<>();

    @Override
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        updateRows();
        return true;
    }

    private void updateRows() {
        rowCount = 0;
        hiddenChatsList.clear();
        // getHiddenDialogIds() returns current mode list (main or decoy)
        hiddenChatsList.addAll(HiddenChatsManager.getInstance().getHiddenDialogIds());

        hideChatsRow = rowCount++;
        unhideChatsRow = rowCount++;
        changePasswordRow = rowCount++;
        decoyPasswordRow = rowCount++;
        forgetPasswordRow = rowCount++;
        askPasswordOnStartRow = rowCount++;
        duplicateDetectionRow = rowCount++;
        sectionRow = rowCount++;
        
        // Encrypted calls section
        encryptedCallsHeaderRow = rowCount++;
        outgoingCallPasswordRow = rowCount++;
        incomingCallsHeaderRow = rowCount++;
        
        java.util.List<org.telegram.messenger.EncryptedCallsManager.IncomingKey> incomingKeys = 
            org.telegram.messenger.EncryptedCallsManager.getInstance().getIncomingKeys();
        if (!incomingKeys.isEmpty()) {
            incomingKeysStartRow = rowCount;
            rowCount += incomingKeys.size();
            incomingKeysEndRow = rowCount;
        } else {
            incomingKeysStartRow = -1;
            incomingKeysEndRow = -1;
        }
        addIncomingKeyRow = rowCount++;
        encryptedCallsInfoRow = rowCount++;
        
        if (!hiddenChatsList.isEmpty()) {
            hiddenChatsHeaderRow = rowCount++;
            hiddenChatsStartRow = rowCount;
            rowCount += hiddenChatsList.size();
            hiddenChatsEndRow = rowCount;
            hiddenChatsInfoRow = rowCount++;
        } else {
            hiddenChatsHeaderRow = -1;
            hiddenChatsStartRow = -1;
            hiddenChatsEndRow = -1;
            hiddenChatsInfoRow = rowCount++;
        }
    }

    @Override
    public View createView(Context context) {
        actionBar.setBackButtonImage(R.drawable.ic_ab_back);
        actionBar.setAllowOverlayTitle(true);
        actionBar.setTitle(LocaleController.getString("HiddenChats", R.string.HiddenChats));
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
            if (position == hideChatsRow) {
                showHideChatDialog();
            } else if (position == unhideChatsRow) {
                showUnhideChatDialog();
            } else if (position == changePasswordRow) {
                showChangePasswordDialog();
            } else if (position == decoyPasswordRow) {
                showDecoyPasswordDialog();
            } else if (position == forgetPasswordRow) {
                toggleForgetPasswordSetting();
            } else if (position == askPasswordOnStartRow) {
                showAskPasswordModeDialog();
            } else if (position == duplicateDetectionRow) {
                showDuplicateDetectionDialog();
            } else if (position == outgoingCallPasswordRow) {
                showOutgoingCallPasswordDialog();
            } else if (position == addIncomingKeyRow) {
                showAddIncomingKeyDialog(-1);
            } else if (position >= incomingKeysStartRow && position < incomingKeysEndRow) {
                int index = position - incomingKeysStartRow;
                showIncomingKeyOptionsDialog(index);
            } else if (position >= hiddenChatsStartRow && position < hiddenChatsEndRow) {
                // Click on hidden chat - show option to unhide
                int index = position - hiddenChatsStartRow;
                if (index >= 0 && index < hiddenChatsList.size()) {
                    long dialogId = hiddenChatsList.get(index);
                    String chatName = getDialogName(dialogId);
                    
                    AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                    builder.setTitle(chatName);
                    builder.setMessage(LocaleController.getString("UnhideThisChat", R.string.UnhideThisChat));
                    builder.setPositiveButton(LocaleController.getString("Unhide", R.string.Unhide), (dialog, which) -> {
                        HiddenChatsManager.getInstance().removeHiddenChat(dialogId);
                        updateRows();
                        if (listAdapter != null) {
                            listAdapter.notifyDataSetChanged();
                        }
                    });
                    builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                    showDialog(builder.create());
                }
            }
        });

        return fragmentView;
    }

    private void showHideChatDialog() {
        // Open dialogs picker to select a chat to hide
        Bundle args = new Bundle();
        args.putBoolean("onlySelect", true);
        args.putBoolean("canSelectTopics", false);
        args.putInt("dialogsType", DialogsActivity.DIALOGS_TYPE_FORWARD);
        args.putString("selectAlertString", LocaleController.getString("SelectChatToHide", R.string.SelectChatToHide));
        // Pass flag to hide main hidden chats in decoy mode
        args.putBoolean("hideMainHiddenChats", HiddenChatsManager.getInstance().isDecoyMode());
        
        DialogsActivity dialogsActivity = new DialogsActivity(args);
        dialogsActivity.setDelegate((fragment, dids, message, param, notify, scheduleDate, topicsFragment) -> {
            if (dids != null && !dids.isEmpty()) {
                long dialogId = dids.get(0).dialogId;
                
                // Close the dialogs picker first
                fragment.finishFragment();
                
                // Check if already hidden in current mode
                if (HiddenChatsManager.getInstance().isHiddenInCurrentMode(dialogId)) {
                    AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                    builder.setTitle(LocaleController.getString("AlreadyHidden", R.string.AlreadyHidden));
                    builder.setMessage(LocaleController.getString("ChatAlreadyHidden", R.string.ChatAlreadyHidden));
                    builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                    showDialog(builder.create());
                    return true;
                }
                
                // Add to hidden chats (adds to current mode's list)
                HiddenChatsManager.getInstance().addHiddenChat(dialogId);
                updateRows();
                if (listAdapter != null) {
                    listAdapter.notifyDataSetChanged();
                }
                
                // Show confirmation
                String chatName = getDialogName(dialogId);
                AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                builder.setTitle(LocaleController.getString("ChatHidden", R.string.ChatHidden));
                builder.setMessage(LocaleController.formatString("ChatHiddenMessage", R.string.ChatHiddenMessage, chatName));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                showDialog(builder.create());
            }
            return true;
        });
        presentFragment(dialogsActivity);
    }

    private void showUnhideChatDialog() {
        Set<Long> hiddenIds = HiddenChatsManager.getInstance().getHiddenDialogIds();
        if (hiddenIds.isEmpty()) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("NoHiddenChats", R.string.NoHiddenChats));
            builder.setMessage(LocaleController.getString("NoHiddenChatsMessage", R.string.NoHiddenChatsMessage));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            showDialog(builder.create());
            return;
        }

        // Create dialog with list of hidden chats
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("SelectChatToUnhide", R.string.SelectChatToUnhide));

        final ArrayList<Long> chatIds = new ArrayList<>(hiddenIds);
        String[] chatNames = new String[chatIds.size()];
        
        for (int i = 0; i < chatIds.size(); i++) {
            long dialogId = chatIds.get(i);
            String name = getDialogName(dialogId);
            chatNames[i] = name != null ? name : "Unknown Chat";
        }

        builder.setItems(chatNames, (dialog, which) -> {
            long dialogId = chatIds.get(which);
            HiddenChatsManager.getInstance().removeHiddenChat(dialogId);
            updateRows();
            if (listAdapter != null) {
                listAdapter.notifyDataSetChanged();
            }
        });

        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
    }

    private String getDialogName(long dialogId) {
        if (DialogObject.isEncryptedDialog(dialogId)) {
            int encryptedChatId = DialogObject.getEncryptedChatId(dialogId);
            TLRPC.EncryptedChat encryptedChat = getMessagesController().getEncryptedChat(encryptedChatId);
            if (encryptedChat != null) {
                TLRPC.User user = getMessagesController().getUser(encryptedChat.user_id);
                if (user != null) {
                    String firstName = user.first_name != null ? user.first_name : "";
                    String lastName = user.last_name != null ? " " + user.last_name : "";
                    return "🔒 " + firstName + lastName;
                }
            }
            return "🔒 Secret Chat";
        } else if (DialogObject.isUserDialog(dialogId)) {
            TLRPC.User user = getMessagesController().getUser(dialogId);
            if (user != null) {
                String firstName = user.first_name != null ? user.first_name : "";
                String lastName = user.last_name != null ? " " + user.last_name : "";
                return firstName + lastName;
            }
        } else if (DialogObject.isChatDialog(dialogId)) {
            TLRPC.Chat chat = getMessagesController().getChat(-dialogId);
            if (chat != null) {
                return chat.title;
            }
        }
        return "Dialog " + dialogId;
    }

    private void showChangePasswordDialog() {
        Context context = getParentActivity();
        if (context == null) return;

        HiddenChatsManager manager = HiddenChatsManager.getInstance();
        
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(LocaleController.getString("ChangePassword", R.string.ChangePassword));

        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(AndroidUtilities.dp(24), AndroidUtilities.dp(8), AndroidUtilities.dp(24), 0);

        final EditTextBoldCursor oldPasswordField = new EditTextBoldCursor(context);
        oldPasswordField.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 16);
        oldPasswordField.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        oldPasswordField.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        oldPasswordField.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
        oldPasswordField.setMaxLines(1);
        oldPasswordField.setLines(1);
        oldPasswordField.setSingleLine(true);
        oldPasswordField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        oldPasswordField.setHint(LocaleController.getString("CurrentPassword", R.string.CurrentPassword));
        layout.addView(oldPasswordField, LayoutHelper.createLinear(LayoutHelper.MATCH_PARENT, 48));

        final EditTextBoldCursor newPasswordField = new EditTextBoldCursor(context);
        newPasswordField.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 16);
        newPasswordField.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        newPasswordField.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        newPasswordField.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
        newPasswordField.setMaxLines(1);
        newPasswordField.setLines(1);
        newPasswordField.setSingleLine(true);
        newPasswordField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        newPasswordField.setHint(LocaleController.getString("NewPassword", R.string.NewPassword));
        layout.addView(newPasswordField, LayoutHelper.createLinear(LayoutHelper.MATCH_PARENT, 48, 0, 8, 0, 0));

        final EditTextBoldCursor confirmPasswordField = new EditTextBoldCursor(context);
        confirmPasswordField.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 16);
        confirmPasswordField.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        confirmPasswordField.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        confirmPasswordField.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
        confirmPasswordField.setMaxLines(1);
        confirmPasswordField.setLines(1);
        confirmPasswordField.setSingleLine(true);
        confirmPasswordField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        confirmPasswordField.setHint(LocaleController.getString("ConfirmNewPassword", R.string.ConfirmNewPassword));
        layout.addView(confirmPasswordField, LayoutHelper.createLinear(LayoutHelper.MATCH_PARENT, 48, 0, 8, 0, 0));

        builder.setView(layout);

        builder.setPositiveButton(LocaleController.getString("Change", R.string.Change), (dialog, which) -> {
            String oldPass = oldPasswordField.getText().toString();
            String newPass = newPasswordField.getText().toString();
            String confirmPass = confirmPasswordField.getText().toString();

            // In decoy mode, check decoy password; in normal mode, check main password
            boolean passwordCorrect;
            if (manager.isDecoyMode()) {
                passwordCorrect = manager.checkDecoyPassword(oldPass);
            } else {
                passwordCorrect = manager.checkMainPassword(oldPass);
            }
            
            if (!passwordCorrect) {
                AlertDialog.Builder errorBuilder = new AlertDialog.Builder(context);
                errorBuilder.setTitle(LocaleController.getString("Error", R.string.Error));
                errorBuilder.setMessage(LocaleController.getString("CurrentPasswordIncorrect", R.string.CurrentPasswordIncorrect));
                errorBuilder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                showDialog(errorBuilder.create());
                return;
            }

            if (TextUtils.isEmpty(newPass)) {
                AlertDialog.Builder errorBuilder = new AlertDialog.Builder(context);
                errorBuilder.setTitle(LocaleController.getString("Error", R.string.Error));
                errorBuilder.setMessage(LocaleController.getString("PasswordCannotBeEmpty", R.string.PasswordCannotBeEmpty));
                errorBuilder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                showDialog(errorBuilder.create());
                return;
            }

            if (!newPass.equals(confirmPass)) {
                AlertDialog.Builder errorBuilder = new AlertDialog.Builder(context);
                errorBuilder.setTitle(LocaleController.getString("Error", R.string.Error));
                errorBuilder.setMessage(LocaleController.getString("PasswordsDoNotMatch", R.string.PasswordsDoNotMatch));
                errorBuilder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                showDialog(errorBuilder.create());
                return;
            }
            
            // Check that new password doesn't match the other password
            if (!manager.isDecoyMode() && manager.isPasswordSameAsDecoy(newPass)) {
                AlertDialog.Builder errorBuilder = new AlertDialog.Builder(context);
                errorBuilder.setTitle(LocaleController.getString("Error", R.string.Error));
                errorBuilder.setMessage(LocaleController.getString("SecurityPasswordMustBeDifferent", R.string.SecurityPasswordMustBeDifferent));
                errorBuilder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                showDialog(errorBuilder.create());
                return;
            }
            if (manager.isDecoyMode() && manager.isPasswordSameAsMain(newPass)) {
                AlertDialog.Builder errorBuilder = new AlertDialog.Builder(context);
                errorBuilder.setTitle(LocaleController.getString("Error", R.string.Error));
                errorBuilder.setMessage(LocaleController.getString("SecurityPasswordMustBeDifferent", R.string.SecurityPasswordMustBeDifferent));
                errorBuilder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                showDialog(errorBuilder.create());
                return;
            }

            // changePassword will change the appropriate password based on mode
            manager.changePassword(newPass);
            
            AlertDialog.Builder successBuilder = new AlertDialog.Builder(context);
            successBuilder.setTitle(LocaleController.getString("Success", R.string.Success));
            successBuilder.setMessage(LocaleController.getString("PasswordChangedSuccessfully", R.string.PasswordChangedSuccessfully));
            successBuilder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            showDialog(successBuilder.create());
        });

        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
    }
    
    private void showDecoyPasswordDialog() {
        Context context = getParentActivity();
        if (context == null) return;
        
        HiddenChatsManager manager = HiddenChatsManager.getInstance();
        
        // In decoy mode - hasDecoyPassword() always returns false
        // So we always show "not set" dialog and pretend to set it
        boolean hasDecoy = manager.hasDecoyPassword();

        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(LocaleController.getString("SecurityPasswordTitle", R.string.SecurityPasswordTitle));
        
        if (hasDecoy) {
            // Has decoy password (only visible in normal mode)
            builder.setMessage(LocaleController.getString("SecurityPasswordIsSet", R.string.SecurityPasswordIsSet));
            
            builder.setPositiveButton(LocaleController.getString("Change", R.string.Change), (dialog, which) -> {
                showSetDecoyPasswordDialog();
            });
            builder.setNeutralButton(LocaleController.getString("Remove", R.string.Remove), (dialog, which) -> {
                manager.removeDecoyPassword();
                if (listAdapter != null) {
                    listAdapter.notifyDataSetChanged();
                }
                AlertDialog.Builder successBuilder = new AlertDialog.Builder(context);
                successBuilder.setTitle(LocaleController.getString("Removed", R.string.Removed));
                successBuilder.setMessage(LocaleController.getString("SecurityPasswordRemoved", R.string.SecurityPasswordRemoved));
                successBuilder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                showDialog(successBuilder.create());
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        } else {
            // No decoy password (or in decoy mode - always shows this)
            builder.setMessage(LocaleController.getString("SecurityPasswordNotSetMessage", R.string.SecurityPasswordNotSetMessage));
            
            builder.setPositiveButton(LocaleController.getString("SetPassword", R.string.SetPassword), (dialog, which) -> {
                showSetDecoyPasswordDialog();
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        }
        
        showDialog(builder.create());
    }
    
    private void showSetDecoyPasswordDialog() {
        Context context = getParentActivity();
        if (context == null) return;

        HiddenChatsManager manager = HiddenChatsManager.getInstance();
        
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(LocaleController.getString("SetSecurityPassword", R.string.SetSecurityPassword));

        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(AndroidUtilities.dp(24), AndroidUtilities.dp(8), AndroidUtilities.dp(24), 0);

        final EditTextBoldCursor passwordField = new EditTextBoldCursor(context);
        passwordField.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 16);
        passwordField.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        passwordField.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        passwordField.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
        passwordField.setMaxLines(1);
        passwordField.setLines(1);
        passwordField.setSingleLine(true);
        passwordField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        passwordField.setHint(LocaleController.getString("SecurityPassword", R.string.SecurityPassword));
        layout.addView(passwordField, LayoutHelper.createLinear(LayoutHelper.MATCH_PARENT, 48));

        final EditTextBoldCursor confirmField = new EditTextBoldCursor(context);
        confirmField.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 16);
        confirmField.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        confirmField.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        confirmField.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
        confirmField.setMaxLines(1);
        confirmField.setLines(1);
        confirmField.setSingleLine(true);
        confirmField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        confirmField.setHint(LocaleController.getString("ConfirmPassword", R.string.ConfirmPassword));
        layout.addView(confirmField, LayoutHelper.createLinear(LayoutHelper.MATCH_PARENT, 48, 0, 8, 0, 0));

        builder.setView(layout);

        builder.setPositiveButton(LocaleController.getString("Set", R.string.Set), (dialog, which) -> {
            String pass = passwordField.getText().toString();
            String confirm = confirmField.getText().toString();

            if (TextUtils.isEmpty(pass)) {
                AlertDialog.Builder errorBuilder = new AlertDialog.Builder(context);
                errorBuilder.setTitle(LocaleController.getString("Error", R.string.Error));
                errorBuilder.setMessage(LocaleController.getString("PasswordCannotBeEmpty", R.string.PasswordCannotBeEmpty));
                errorBuilder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                showDialog(errorBuilder.create());
                return;
            }

            if (!pass.equals(confirm)) {
                AlertDialog.Builder errorBuilder = new AlertDialog.Builder(context);
                errorBuilder.setTitle(LocaleController.getString("Error", R.string.Error));
                errorBuilder.setMessage(LocaleController.getString("PasswordsDoNotMatch", R.string.PasswordsDoNotMatch));
                errorBuilder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                showDialog(errorBuilder.create());
                return;
            }
            
            // In decoy mode - pretend we're setting it but do nothing
            // setDecoyPassword handles this internally
            if (!manager.isDecoyMode()) {
                // Only in normal mode - check that password is different from main
                if (manager.isPasswordSameAsMain(pass)) {
                    AlertDialog.Builder errorBuilder = new AlertDialog.Builder(context);
                    errorBuilder.setTitle(LocaleController.getString("Error", R.string.Error));
                    errorBuilder.setMessage(LocaleController.getString("SecurityPasswordMustBeDifferent", R.string.SecurityPasswordMustBeDifferent));
                    errorBuilder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                    showDialog(errorBuilder.create());
                    return;
                }
            }

            manager.setDecoyPassword(pass);
            if (listAdapter != null) {
                listAdapter.notifyDataSetChanged();
            }
            
            AlertDialog.Builder successBuilder = new AlertDialog.Builder(context);
            successBuilder.setTitle(LocaleController.getString("Success", R.string.Success));
            successBuilder.setMessage(LocaleController.getString("SecurityPasswordSetSuccess", R.string.SecurityPasswordSetSuccess));
            successBuilder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            showDialog(successBuilder.create());
        });

        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
    }
    
    private void toggleForgetPasswordSetting() {
        HiddenChatsManager manager = HiddenChatsManager.getInstance();
        boolean currentValue = manager.isForgetPasswordOnMinimize();
        manager.setForgetPasswordOnMinimize(!currentValue);
        
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }
    
    private void showAskPasswordModeDialog() {
        Context context = getParentActivity();
        if (context == null) return;
        
        String[] items = new String[]{
            LocaleController.getString("AskPasswordDisabled", R.string.AskPasswordDisabled),
            LocaleController.getString("AskPasswordAlways", R.string.AskPasswordAlways),
            LocaleController.getString("AskPasswordIfEncrypted", R.string.AskPasswordIfEncrypted)
        };
        
        int currentMode = HiddenChatsManager.getInstance().getAskPasswordOnStartMode();
        
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(LocaleController.getString("AskPasswordOnStart", R.string.AskPasswordOnStart));
        builder.setItems(items, (dialog, which) -> {
            HiddenChatsManager.getInstance().setAskPasswordOnStartMode(which);
            if (listAdapter != null) {
                listAdapter.notifyDataSetChanged();
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.show();
    }
    
    private void showDuplicateDetectionDialog() {
        Context context = getParentActivity();
        if (context == null) return;
        
        EncryptedMessagesManager encManager = EncryptedMessagesManager.getInstance();
        int currentCount = encManager.getDuplicateDetectionCount();
        
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(LocaleController.getString("DuplicateDetection", R.string.DuplicateDetection));
        
        // Create input field
        final android.widget.EditText input = new android.widget.EditText(context);
        input.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        input.setHint("0 = " + LocaleController.getString("Disabled", R.string.Disabled));
        input.setText(String.valueOf(currentCount));
        input.setSelection(input.getText().length());
        
        android.widget.FrameLayout container = new android.widget.FrameLayout(context);
        android.widget.FrameLayout.LayoutParams params = new android.widget.FrameLayout.LayoutParams(
            android.widget.FrameLayout.LayoutParams.MATCH_PARENT,
            android.widget.FrameLayout.LayoutParams.WRAP_CONTENT
        );
        params.leftMargin = AndroidUtilities.dp(24);
        params.rightMargin = AndroidUtilities.dp(24);
        params.topMargin = AndroidUtilities.dp(8);
        input.setLayoutParams(params);
        container.addView(input);
        
        builder.setView(container);
        builder.setMessage(LocaleController.getString("DuplicateDetectionInfo", R.string.DuplicateDetectionInfo));
        
        builder.setPositiveButton(LocaleController.getString("Save", R.string.Save), (dialog, which) -> {
            try {
                int count = Integer.parseInt(input.getText().toString().trim());
                if (count < 0) count = 0;
                encManager.setDuplicateDetectionCount(count);
                if (listAdapter != null) {
                    listAdapter.notifyDataSetChanged();
                }
            } catch (NumberFormatException e) {
                // Invalid input, ignore
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.show();
    }
    
    private void showOutgoingCallPasswordDialog() {
        Context context = getParentActivity();
        if (context == null) return;
        
        org.telegram.messenger.EncryptedCallsManager manager = org.telegram.messenger.EncryptedCallsManager.getInstance();
        String currentPassword = manager.getOutgoingPassword();
        
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(LocaleController.getString("OutgoingCallPassword", R.string.OutgoingCallPassword));
        
        final android.widget.EditText input = new android.widget.EditText(context);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        input.setHint(LocaleController.getString("EnterPassword", R.string.EnterPassword));
        if (currentPassword != null) {
            input.setText(currentPassword);
            input.setSelection(input.getText().length());
        }
        
        android.widget.FrameLayout container = new android.widget.FrameLayout(context);
        android.widget.FrameLayout.LayoutParams params = new android.widget.FrameLayout.LayoutParams(
            android.widget.FrameLayout.LayoutParams.MATCH_PARENT,
            android.widget.FrameLayout.LayoutParams.WRAP_CONTENT
        );
        params.leftMargin = AndroidUtilities.dp(24);
        params.rightMargin = AndroidUtilities.dp(24);
        params.topMargin = AndroidUtilities.dp(8);
        input.setLayoutParams(params);
        container.addView(input);
        
        builder.setView(container);
        builder.setMessage(LocaleController.getString("OutgoingCallPasswordInfo", R.string.OutgoingCallPasswordInfo));
        
        builder.setPositiveButton(LocaleController.getString("Save", R.string.Save), (dialog, which) -> {
            String password = input.getText().toString().trim();
            manager.setOutgoingPassword(password.isEmpty() ? null : password);
            if (listAdapter != null) {
                listAdapter.notifyDataSetChanged();
            }
        });
        
        if (currentPassword != null) {
            builder.setNeutralButton(LocaleController.getString("Remove", R.string.Remove), (dialog, which) -> {
                manager.setOutgoingPassword(null);
                if (listAdapter != null) {
                    listAdapter.notifyDataSetChanged();
                }
            });
        }
        
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.show();
    }
    
    private void showAddIncomingKeyDialog(int editIndex) {
        Context context = getParentActivity();
        if (context == null) return;
        
        org.telegram.messenger.EncryptedCallsManager manager = org.telegram.messenger.EncryptedCallsManager.getInstance();
        org.telegram.messenger.EncryptedCallsManager.IncomingKey existingKey = null;
        if (editIndex >= 0) {
            java.util.List<org.telegram.messenger.EncryptedCallsManager.IncomingKey> keys = manager.getIncomingKeys();
            if (editIndex < keys.size()) {
                existingKey = keys.get(editIndex);
            }
        }
        
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(editIndex >= 0 ? 
            LocaleController.getString("EditIncomingKey", R.string.EditIncomingKey) :
            LocaleController.getString("AddIncomingKey", R.string.AddIncomingKey));
        
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(AndroidUtilities.dp(24), AndroidUtilities.dp(8), AndroidUtilities.dp(24), 0);
        
        final android.widget.EditText nameInput = new android.widget.EditText(context);
        nameInput.setHint(LocaleController.getString("KeyName", R.string.KeyName));
        nameInput.setInputType(InputType.TYPE_CLASS_TEXT);
        if (existingKey != null) {
            nameInput.setText(existingKey.name);
        }
        layout.addView(nameInput);
        
        final android.widget.EditText passwordInput = new android.widget.EditText(context);
        passwordInput.setHint(LocaleController.getString("Password", R.string.Password));
        passwordInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        if (existingKey != null) {
            passwordInput.setText(existingKey.password);
        }
        layout.addView(passwordInput);
        
        builder.setView(layout);
        
        final int finalEditIndex = editIndex;
        final org.telegram.messenger.EncryptedCallsManager.IncomingKey finalExistingKey = existingKey;
        
        builder.setPositiveButton(LocaleController.getString("Save", R.string.Save), (dialog, which) -> {
            String name = nameInput.getText().toString().trim();
            String password = passwordInput.getText().toString().trim();
            
            if (name.isEmpty()) {
                name = "Key " + (manager.getIncomingKeys().size() + 1);
            }
            if (password.isEmpty()) {
                return;
            }
            
            if (finalEditIndex >= 0 && finalExistingKey != null) {
                manager.updateIncomingKey(finalEditIndex, name, password, finalExistingKey.enabled);
            } else {
                manager.addIncomingKey(name, password);
            }
            
            updateRows();
            if (listAdapter != null) {
                listAdapter.notifyDataSetChanged();
            }
        });
        
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.show();
    }
    
    private void showIncomingKeyOptionsDialog(int index) {
        Context context = getParentActivity();
        if (context == null) return;
        
        org.telegram.messenger.EncryptedCallsManager manager = org.telegram.messenger.EncryptedCallsManager.getInstance();
        java.util.List<org.telegram.messenger.EncryptedCallsManager.IncomingKey> keys = manager.getIncomingKeys();
        if (index < 0 || index >= keys.size()) return;
        
        org.telegram.messenger.EncryptedCallsManager.IncomingKey key = keys.get(index);
        
        String[] items = new String[]{
            LocaleController.getString("Edit", R.string.Edit),
            key.enabled ? LocaleController.getString("Disable", R.string.Disable) : LocaleController.getString("Enable", R.string.Enable),
            LocaleController.getString("Delete", R.string.Delete)
        };
        
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(key.name);
        builder.setItems(items, (dialog, which) -> {
            if (which == 0) {
                showAddIncomingKeyDialog(index);
            } else if (which == 1) {
                manager.setIncomingKeyEnabled(index, !key.enabled);
                if (listAdapter != null) {
                    listAdapter.notifyDataSetChanged();
                }
            } else if (which == 2) {
                manager.removeIncomingKey(index);
                updateRows();
                if (listAdapter != null) {
                    listAdapter.notifyDataSetChanged();
                }
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.show();
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            mContext = context;
        }

        @Override
        public int getItemCount() {
            return rowCount;
        }

        @Override
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int type = holder.getItemViewType();
            return type == 0 || type == 3;
        }

        @Override
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            switch (viewType) {
                case 0:
                    view = new TextCell(mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 1:
                    view = new TextInfoPrivacyCell(mContext);
                    break;
                case 2:
                    view = new HeaderCell(mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 3:
                default:
                    view = new TextCell(mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
            }
            return new RecyclerListView.Holder(view);
        }

        @Override
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            switch (holder.getItemViewType()) {
                case 0: {
                    TextCell textCell = (TextCell) holder.itemView;
                    if (position == hideChatsRow) {
                        textCell.setTextAndIcon(LocaleController.getString("HideChat", R.string.HideChat), R.drawable.msg_secret, true);
                    } else if (position == unhideChatsRow) {
                        textCell.setTextAndIcon(LocaleController.getString("UnhideChat", R.string.UnhideChat), R.drawable.msg_openprofile, true);
                    } else if (position == changePasswordRow) {
                        textCell.setTextAndIcon(LocaleController.getString("ChangePassword", R.string.ChangePassword), R.drawable.msg_permissions, true);
                    } else if (position == decoyPasswordRow) {
                        // In decoy mode, hasDecoyPassword() always returns false
                        String status = HiddenChatsManager.getInstance().hasDecoyPassword() 
                            ? " (" + LocaleController.getString("SecurityPasswordSet", R.string.SecurityPasswordSet) + ")" 
                            : " (" + LocaleController.getString("SecurityPasswordNotSet", R.string.SecurityPasswordNotSet) + ")";
                        textCell.setTextAndIcon(LocaleController.getString("SecurityPassword", R.string.SecurityPassword) + status, R.drawable.msg_secret, true);
                    } else if (position == forgetPasswordRow) {
                        boolean isEnabled = HiddenChatsManager.getInstance().isForgetPasswordOnMinimize();
                        String status = isEnabled 
                            ? " (" + LocaleController.getString("NotificationsOn", R.string.NotificationsOn) + ")" 
                            : " (" + LocaleController.getString("NotificationsOff", R.string.NotificationsOff) + ")";
                        textCell.setTextAndIcon(LocaleController.getString("ForgetPasswordOnMinimize", R.string.ForgetPasswordOnMinimize) + status, R.drawable.msg_autodelete, true);
                    } else if (position == askPasswordOnStartRow) {
                        int mode = HiddenChatsManager.getInstance().getAskPasswordOnStartMode();
                        String status;
                        switch (mode) {
                            case HiddenChatsManager.ASK_PASSWORD_ALWAYS:
                                status = LocaleController.getString("AskPasswordAlways", R.string.AskPasswordAlways);
                                break;
                            case HiddenChatsManager.ASK_PASSWORD_IF_ENCRYPTED_CHATS:
                                status = LocaleController.getString("AskPasswordIfEncryptedShort", R.string.AskPasswordIfEncryptedShort);
                                break;
                            default:
                                status = LocaleController.getString("AskPasswordDisabled", R.string.AskPasswordDisabled);
                                break;
                        }
                        textCell.setTextAndValue(LocaleController.getString("AskPasswordOnStart", R.string.AskPasswordOnStart), status, true);
                    } else if (position == duplicateDetectionRow) {
                        int count = EncryptedMessagesManager.getInstance().getDuplicateDetectionCount();
                        String status = count > 0 ? String.valueOf(count) : LocaleController.getString("Disabled", R.string.Disabled);
                        textCell.setTextAndValue(LocaleController.getString("DuplicateDetection", R.string.DuplicateDetection), status, false);
                    } else if (position == outgoingCallPasswordRow) {
                        org.telegram.messenger.EncryptedCallsManager callsManager = org.telegram.messenger.EncryptedCallsManager.getInstance();
                        boolean hasPassword = callsManager.hasOutgoingPassword();
                        String status = hasPassword ? "🔒" : "⚠️";
                        textCell.setTextAndValue(LocaleController.getString("OutgoingCallPassword", R.string.OutgoingCallPassword), status, true);
                    } else if (position == addIncomingKeyRow) {
                        textCell.setTextAndIcon(LocaleController.getString("AddIncomingKey", R.string.AddIncomingKey), R.drawable.msg_add, false);
                        textCell.setColors(Theme.key_windowBackgroundWhiteBlueText4, Theme.key_windowBackgroundWhiteBlueText4);
                    }
                    break;
                }
                case 1: {
                    TextInfoPrivacyCell cell = (TextInfoPrivacyCell) holder.itemView;
                    if (position == sectionRow) {
                        cell.setText("");
                        cell.setBackground(Theme.getThemedDrawableByKey(mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                    } else if (position == encryptedCallsInfoRow) {
                        cell.setText(LocaleController.getString("EncryptedCallsInfo", R.string.EncryptedCallsInfo));
                        cell.setBackground(Theme.getThemedDrawableByKey(mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                    } else if (position == hiddenChatsInfoRow) {
                        if (hiddenChatsList.isEmpty()) {
                            cell.setText(LocaleController.getString("NoHiddenChatsYet", R.string.NoHiddenChatsYet));
                        } else {
                            cell.setText(LocaleController.getString("HiddenChatsInfo", R.string.HiddenChatsInfo));
                        }
                        cell.setBackground(Theme.getThemedDrawableByKey(mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                    }
                    break;
                }
                case 2: {
                    HeaderCell cell = (HeaderCell) holder.itemView;
                    if (position == encryptedCallsHeaderRow) {
                        cell.setText(LocaleController.getString("EncryptedCalls", R.string.EncryptedCalls));
                    } else if (position == incomingCallsHeaderRow) {
                        cell.setText(LocaleController.getString("IncomingCallKeys", R.string.IncomingCallKeys));
                    } else if (position == hiddenChatsHeaderRow) {
                        cell.setText(LocaleController.formatString("HiddenChatsCount", R.string.HiddenChatsCount, hiddenChatsList.size()));
                    }
                    break;
                }
                case 3: {
                    TextCell cell = (TextCell) holder.itemView;
                    // Check if it's incoming key row
                    if (position >= incomingKeysStartRow && position < incomingKeysEndRow) {
                        int index = position - incomingKeysStartRow;
                        java.util.List<org.telegram.messenger.EncryptedCallsManager.IncomingKey> keys = 
                            org.telegram.messenger.EncryptedCallsManager.getInstance().getIncomingKeys();
                        if (index >= 0 && index < keys.size()) {
                            org.telegram.messenger.EncryptedCallsManager.IncomingKey key = keys.get(index);
                            String status = key.enabled ? "🔒" : "⚫";
                            boolean needDivider = index < keys.size() - 1;
                            cell.setTextAndValue(key.name, status, needDivider);
                            cell.setColors(
                                key.enabled ? Theme.key_windowBackgroundWhiteBlackText : Theme.key_windowBackgroundWhiteGrayText,
                                Theme.key_windowBackgroundWhiteGrayText2
                            );
                        }
                    } else {
                        // Hidden chats row
                        int index = position - hiddenChatsStartRow;
                        if (index >= 0 && index < hiddenChatsList.size()) {
                            long dialogId = hiddenChatsList.get(index);
                            String name = getDialogName(dialogId);
                            
                            int iconRes;
                            if (DialogObject.isEncryptedDialog(dialogId)) {
                                iconRes = R.drawable.msg_secret;
                            } else if (DialogObject.isChatDialog(dialogId)) {
                                TLRPC.Chat chat = getMessagesController().getChat(-dialogId);
                                if (chat != null && (chat.megagroup || chat.gigagroup)) {
                                    iconRes = R.drawable.msg_groups;
                                } else if (chat != null && chat.broadcast) {
                                    iconRes = R.drawable.msg_channel;
                                } else {
                                    iconRes = R.drawable.msg_groups;
                                }
                            } else {
                                iconRes = R.drawable.msg_contacts;
                            }
                            
                            boolean needDivider = index < hiddenChatsList.size() - 1;
                            cell.setTextAndIcon(name, iconRes, needDivider);
                        }
                    }
                    break;
                }
            }
        }

        @Override
        public int getItemViewType(int position) {
            if (position == hideChatsRow || position == unhideChatsRow || position == changePasswordRow 
                    || position == decoyPasswordRow || position == forgetPasswordRow 
                    || position == askPasswordOnStartRow || position == duplicateDetectionRow
                    || position == outgoingCallPasswordRow || position == addIncomingKeyRow) {
                return 0;
            } else if (position == sectionRow || position == hiddenChatsInfoRow || position == encryptedCallsInfoRow) {
                return 1;
            } else if (position == hiddenChatsHeaderRow || position == encryptedCallsHeaderRow || position == incomingCallsHeaderRow) {
                return 2;
            } else if ((position >= incomingKeysStartRow && position < incomingKeysEndRow) 
                    || (position >= hiddenChatsStartRow && position < hiddenChatsEndRow)) {
                return 3;
            }
            return 0;
        }
    }
}
