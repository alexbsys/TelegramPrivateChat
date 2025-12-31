/*
 * Advanced Call Settings Activity
 * Allows configuring custom TURN servers for calls
 */

package org.telegram.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.text.InputType;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.CallServerManager;
import org.telegram.messenger.CallSettingsManager;
import org.telegram.ui.Components.BulletinFactory;
import org.telegram.messenger.LocaleController;
import org.telegram.messenger.R;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.ActionBar.ThemeDescription;
import org.telegram.ui.Cells.HeaderCell;
import org.telegram.ui.Cells.TextCell;
import org.telegram.ui.Cells.TextCheckCell;
import org.telegram.ui.Cells.TextInfoPrivacyCell;
import org.telegram.ui.Components.EditTextBoldCursor;
import org.telegram.ui.Components.LayoutHelper;
import org.telegram.ui.Components.RecyclerListView;

import java.util.ArrayList;
import java.util.List;

public class AdvancedCallSettingsActivity extends BaseFragment {

    private RecyclerListView listView;
    private ListAdapter listAdapter;

    // Row indices
    private int rowCount;
    private int serverModeHeaderRow;
    private int useCallServerRow;
    private int callServerUrlRow;
    private int checkTariffRow;
    private int tariffInfoRow;
    private int serverModeInfoRow;
    private int settingsHeaderRow;
    private int forceWebRTCRow;
    private int useTCPRow;
    private int disableP2PRow;
    private int replaceStandardRow;
    private int settingsInfoRow;
    private int shareSettingsRow;
    private int importSettingsRow;
    private int turnServersHeaderRow;
    private int turnServersStartRow;
    private int turnServersEndRow;
    private int addTurnServerRow;
    private int turnServersInfoRow;

    @Override
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        updateRows();
        return true;
    }

    private void updateRows() {
        rowCount = 0;
        boolean useCallServer = CallSettingsManager.getInstance().isUseCallServer();
        
        // Server mode section
        serverModeHeaderRow = rowCount++;
        useCallServerRow = rowCount++;
        if (useCallServer) {
            callServerUrlRow = rowCount++;
            checkTariffRow = rowCount++;
            tariffInfoRow = rowCount++;
        } else {
            callServerUrlRow = -1;
            checkTariffRow = -1;
            tariffInfoRow = -1;
        }
        serverModeInfoRow = rowCount++;
        
        // Hide manual settings when server mode is enabled
        if (!useCallServer) {
            // WebRTC settings section
            settingsHeaderRow = rowCount++;
            forceWebRTCRow = rowCount++;
            useTCPRow = rowCount++;
            disableP2PRow = rowCount++;
            replaceStandardRow = rowCount++;
            settingsInfoRow = rowCount++;
            shareSettingsRow = rowCount++;
            importSettingsRow = rowCount++;
            
            turnServersHeaderRow = rowCount++;
            
            List<CallSettingsManager.TurnServer> servers = CallSettingsManager.getInstance().getCustomTurnServers();
            if (!servers.isEmpty()) {
                turnServersStartRow = rowCount;
                rowCount += servers.size();
                turnServersEndRow = rowCount;
            } else {
                turnServersStartRow = -1;
                turnServersEndRow = -1;
            }
            
            addTurnServerRow = rowCount++;
            turnServersInfoRow = rowCount++;
        } else {
            // Hide all manual settings
            settingsHeaderRow = -1;
            forceWebRTCRow = -1;
            useTCPRow = -1;
            disableP2PRow = -1;
            replaceStandardRow = -1;
            settingsInfoRow = -1;
            shareSettingsRow = -1;
            importSettingsRow = -1;
            turnServersHeaderRow = -1;
            turnServersStartRow = -1;
            turnServersEndRow = -1;
            addTurnServerRow = -1;
            turnServersInfoRow = -1;
        }
    }

    @Override
    public View createView(Context context) {
        actionBar.setBackButtonImage(R.drawable.ic_ab_back);
        actionBar.setAllowOverlayTitle(true);
        actionBar.setTitle(LocaleController.getString("AdvancedCallSettings", R.string.AdvancedCallSettings));
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
            if (position == useCallServerRow) {
                CallSettingsManager manager = CallSettingsManager.getInstance();
                boolean newValue = !manager.isUseCallServer();
                manager.setUseCallServer(newValue);
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(newValue);
                }
                updateRows();
                listAdapter.notifyDataSetChanged();
            } else if (position == callServerUrlRow) {
                showCallServerUrlDialog();
            } else if (position == checkTariffRow) {
                checkTariff();
            } else if (position == forceWebRTCRow) {
                CallSettingsManager manager = CallSettingsManager.getInstance();
                manager.setForceWebRTC(!manager.isForceWebRTC());
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(manager.isForceWebRTC());
                }
            } else if (position == useTCPRow) {
                CallSettingsManager manager = CallSettingsManager.getInstance();
                manager.setUseTCP(!manager.isUseTCP());
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(manager.isUseTCP());
                }
            } else if (position == disableP2PRow) {
                CallSettingsManager manager = CallSettingsManager.getInstance();
                manager.setDisableP2P(!manager.isDisableP2P());
                if (view instanceof TextCheckCell) {
                    ((TextCheckCell) view).setChecked(manager.isDisableP2P());
                }
            } else if (position == replaceStandardRow) {
                CallSettingsManager manager = CallSettingsManager.getInstance();
                boolean newValue = !manager.isReplaceStandardServers();
                if (newValue && manager.getEnabledTurnServers().isEmpty()) {
                    // Warn user that they need to add TURN servers first
                    showWarningDialog(LocaleController.getString("ReplaceStandardWarningNoServers", R.string.ReplaceStandardWarningNoServers));
                    return;
                }
                if (newValue) {
                    // Show warning about compatibility
                    showReplaceStandardWarning(() -> {
                        manager.setReplaceStandardServers(true);
                        if (view instanceof TextCheckCell) {
                            ((TextCheckCell) view).setChecked(true);
                        }
                    });
                } else {
                    manager.setReplaceStandardServers(false);
                    if (view instanceof TextCheckCell) {
                        ((TextCheckCell) view).setChecked(false);
                    }
                }
            } else if (position == addTurnServerRow) {
                showAddTurnServerDialog(null, -1);
            } else if (position == shareSettingsRow) {
                shareSettings();
            } else if (position == importSettingsRow) {
                importSettingsFromClipboard();
            } else if (position >= turnServersStartRow && position < turnServersEndRow) {
                int index = position - turnServersStartRow;
                List<CallSettingsManager.TurnServer> servers = CallSettingsManager.getInstance().getCustomTurnServers();
                if (index >= 0 && index < servers.size()) {
                    showTurnServerOptionsDialog(servers.get(index), index);
                }
            }
        });

        return fragmentView;
    }

    private void showAddTurnServerDialog(CallSettingsManager.TurnServer existing, int editIndex) {
        Context context = getParentActivity();
        if (context == null) return;

        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(editIndex >= 0 ? 
            LocaleController.getString("EditTurnServer", R.string.EditTurnServer) : 
            LocaleController.getString("AddTurnServer", R.string.AddTurnServer));

        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(AndroidUtilities.dp(24), AndroidUtilities.dp(8), AndroidUtilities.dp(24), 0);

        // Server type selector (TURN / STUN)
        final int[] selectedType = {existing != null ? existing.serverType : CallSettingsManager.SERVER_TYPE_TURN};
        
        LinearLayout typeLayout = new LinearLayout(context);
        typeLayout.setOrientation(LinearLayout.HORIZONTAL);
        typeLayout.setGravity(Gravity.CENTER_VERTICAL);
        
        TextView typeLabel = new TextView(context);
        typeLabel.setText(LocaleController.getString("ServerType", R.string.ServerType) + ": ");
        typeLabel.setTextSize(16);
        typeLayout.addView(typeLabel);
        
        TextView typeValue = new TextView(context);
        typeValue.setText(selectedType[0] == CallSettingsManager.SERVER_TYPE_TURN ? "TURN" : "STUN");
        typeValue.setTextSize(16);
        typeValue.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText4));
        typeValue.setPadding(AndroidUtilities.dp(8), 0, 0, 0);
        typeValue.setOnClickListener(v -> {
            // Toggle between TURN and STUN
            selectedType[0] = selectedType[0] == CallSettingsManager.SERVER_TYPE_TURN ? 
                CallSettingsManager.SERVER_TYPE_STUN : CallSettingsManager.SERVER_TYPE_TURN;
            typeValue.setText(selectedType[0] == CallSettingsManager.SERVER_TYPE_TURN ? "TURN" : "STUN");
        });
        typeLayout.addView(typeValue);
        
        layout.addView(typeLayout, LayoutHelper.createLinear(LayoutHelper.MATCH_PARENT, 48));

        // Host
        EditTextBoldCursor hostEdit = new EditTextBoldCursor(context);
        hostEdit.setHint(LocaleController.getString("TurnServerHost", R.string.TurnServerHost));
        hostEdit.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        hostEdit.setTextSize(16);
        hostEdit.setSingleLine(true);
        hostEdit.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
        if (existing != null) hostEdit.setText(existing.host);
        layout.addView(hostEdit, LayoutHelper.createLinear(LayoutHelper.MATCH_PARENT, 48));

        // Port
        EditTextBoldCursor portEdit = new EditTextBoldCursor(context);
        portEdit.setHint(LocaleController.getString("TurnServerPort", R.string.TurnServerPort) + " (3478)");
        portEdit.setInputType(InputType.TYPE_CLASS_NUMBER);
        portEdit.setTextSize(16);
        portEdit.setSingleLine(true);
        portEdit.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
        if (existing != null && existing.port > 0) portEdit.setText(String.valueOf(existing.port));
        layout.addView(portEdit, LayoutHelper.createLinear(LayoutHelper.MATCH_PARENT, 48));

        // Username (only for TURN, but show for both)
        EditTextBoldCursor userEdit = new EditTextBoldCursor(context);
        userEdit.setHint(LocaleController.getString("TurnServerUsername", R.string.TurnServerUsername) + " (TURN)");
        userEdit.setInputType(InputType.TYPE_CLASS_TEXT);
        userEdit.setTextSize(16);
        userEdit.setSingleLine(true);
        userEdit.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
        if (existing != null) userEdit.setText(existing.username);
        layout.addView(userEdit, LayoutHelper.createLinear(LayoutHelper.MATCH_PARENT, 48));

        // Password (only for TURN, but show for both)
        EditTextBoldCursor passEdit = new EditTextBoldCursor(context);
        passEdit.setHint(LocaleController.getString("TurnServerPassword", R.string.TurnServerPassword) + " (TURN)");
        passEdit.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        passEdit.setTextSize(16);
        passEdit.setSingleLine(true);
        passEdit.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
        if (existing != null) passEdit.setText(existing.password);
        layout.addView(passEdit, LayoutHelper.createLinear(LayoutHelper.MATCH_PARENT, 48));

        builder.setView(layout);
        builder.setPositiveButton(LocaleController.getString("Save", R.string.Save), (dialog, which) -> {
            String host = hostEdit.getText().toString().trim();
            String portStr = portEdit.getText().toString().trim();
            String username = userEdit.getText().toString().trim();
            String password = passEdit.getText().toString().trim();

            if (TextUtils.isEmpty(host)) {
                return;
            }

            int port = 3478;
            try {
                if (!TextUtils.isEmpty(portStr)) {
                    port = Integer.parseInt(portStr);
                }
            } catch (NumberFormatException e) {
                port = 3478;
            }

            CallSettingsManager.TurnServer server = new CallSettingsManager.TurnServer(host, port, username, password, selectedType[0]);
            
            if (editIndex >= 0) {
                CallSettingsManager.getInstance().updateTurnServer(editIndex, server);
            } else {
                CallSettingsManager.getInstance().addTurnServer(server);
            }
            
            updateRows();
            listAdapter.notifyDataSetChanged();
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.show();
    }

    private void showWarningDialog(String message) {
        Context context = getParentActivity();
        if (context == null) return;
        
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(LocaleController.getString("Warning", R.string.Warning));
        builder.setMessage(message);
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        builder.show();
    }
    
    private void showReplaceStandardWarning(Runnable onConfirm) {
        Context context = getParentActivity();
        if (context == null) return;
        
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle("⚠️ " + LocaleController.getString("Warning", R.string.Warning));
        builder.setMessage(LocaleController.getString("ReplaceStandardWarning", R.string.ReplaceStandardWarning));
        builder.setPositiveButton(LocaleController.getString("Continue", R.string.Continue), (dialog, which) -> {
            if (onConfirm != null) {
                onConfirm.run();
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.show();
    }
    
    private void showTurnServerOptionsDialog(CallSettingsManager.TurnServer server, int index) {
        Context context = getParentActivity();
        if (context == null) return;

        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(server.host + ":" + server.port);
        
        String[] items = new String[]{
            server.enabled ? 
                LocaleController.getString("Disable", R.string.Disable) : 
                LocaleController.getString("Enable", R.string.Enable),
            LocaleController.getString("Edit", R.string.Edit),
            LocaleController.getString("Delete", R.string.Delete)
        };
        
        builder.setItems(items, (dialog, which) -> {
            if (which == 0) {
                CallSettingsManager.getInstance().toggleTurnServer(index);
                listAdapter.notifyDataSetChanged();
            } else if (which == 1) {
                showAddTurnServerDialog(server, index);
            } else if (which == 2) {
                CallSettingsManager.getInstance().removeTurnServer(index);
                updateRows();
                listAdapter.notifyDataSetChanged();
            }
        });
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
            return type == 1 || type == 2 || type == 3;
        }

        @Override
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            switch (viewType) {
                case 0: // Header
                    view = new HeaderCell(mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 1: // TextCell (clickable)
                    view = new TextCell(mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 2: // TextCheckCell
                    view = new TextCheckCell(mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 3: // Turn server item
                    view = new TextCell(mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 4: // Info
                default:
                    view = new TextInfoPrivacyCell(mContext);
                    break;
            }
            return new RecyclerListView.Holder(view);
        }

        @Override
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            switch (holder.getItemViewType()) {
                case 0: // Header
                    HeaderCell headerCell = (HeaderCell) holder.itemView;
                    if (position == serverModeHeaderRow) {
                        headerCell.setText(LocaleController.getString("CallServerMode", R.string.CallServerMode));
                    } else if (position == settingsHeaderRow) {
                        headerCell.setText(LocaleController.getString("CallSettings", R.string.CallSettings));
                    } else if (position == turnServersHeaderRow) {
                        headerCell.setText(LocaleController.getString("TurnServers", R.string.TurnServers));
                    }
                    break;
                case 1: // TextCell
                    TextCell textCell = (TextCell) holder.itemView;
                    if (position == addTurnServerRow) {
                        textCell.setTextAndIcon(LocaleController.getString("AddTurnServer", R.string.AddTurnServer), R.drawable.msg_add, false);
                        textCell.setColors(Theme.key_windowBackgroundWhiteBlueText4, Theme.key_windowBackgroundWhiteBlueText4);
                    } else if (position == shareSettingsRow) {
                        textCell.setTextAndIcon(LocaleController.getString("ShareCallSettings", R.string.ShareCallSettings), R.drawable.msg_share, true);
                        textCell.setColors(Theme.key_windowBackgroundWhiteBlueText4, Theme.key_windowBackgroundWhiteBlueText4);
                    } else if (position == importSettingsRow) {
                        textCell.setTextAndIcon(LocaleController.getString("ImportCallSettings", R.string.ImportCallSettings), R.drawable.msg_download, false);
                        textCell.setColors(Theme.key_windowBackgroundWhiteBlueText4, Theme.key_windowBackgroundWhiteBlueText4);
                    } else if (position == callServerUrlRow) {
                        String url = CallSettingsManager.getInstance().getCallServerUrl();
                        String value = (url != null && !url.isEmpty()) ? url : LocaleController.getString("NotSet", R.string.NotSet);
                        textCell.setTextAndValue(LocaleController.getString("CallServerUrl", R.string.CallServerUrl), value, true);
                    } else if (position == checkTariffRow) {
                        textCell.setTextAndIcon(LocaleController.getString("CheckTariff", R.string.CheckTariff), R.drawable.msg_info, true);
                        textCell.setColors(Theme.key_windowBackgroundWhiteBlueText4, Theme.key_windowBackgroundWhiteBlueText4);
                    } else if (position == tariffInfoRow) {
                        textCell.setText(LocaleController.getString("TariffInfoHint", R.string.TariffInfoHint), false);
                    }
                    break;
                case 2: // TextCheckCell
                    TextCheckCell checkCell = (TextCheckCell) holder.itemView;
                    CallSettingsManager manager = CallSettingsManager.getInstance();
                    if (position == useCallServerRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("UseCallServer", R.string.UseCallServer), manager.isUseCallServer(), true);
                    } else if (position == forceWebRTCRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("ForceWebRTC", R.string.ForceWebRTC), manager.isForceWebRTC(), true);
                    } else if (position == useTCPRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("UseTCPForTurn", R.string.UseTCPForTurn), manager.isUseTCP(), true);
                    } else if (position == disableP2PRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("DisableP2P", R.string.DisableP2P), manager.isDisableP2P(), true);
                    } else if (position == replaceStandardRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("ReplaceStandardServers", R.string.ReplaceStandardServers), manager.isReplaceStandardServers(), false);
                    }
                    break;
                case 3: // Turn/Stun server
                    TextCell serverCell = (TextCell) holder.itemView;
                    int index = position - turnServersStartRow;
                    List<CallSettingsManager.TurnServer> servers = CallSettingsManager.getInstance().getCustomTurnServers();
                    if (index >= 0 && index < servers.size()) {
                        CallSettingsManager.TurnServer server = servers.get(index);
                        String typeStr = server.isStun() ? "STUN" : "TURN";
                        String status = (server.enabled ? "✓ " : "✗ ") + typeStr;
                        serverCell.setTextAndValue(server.host + ":" + server.port, status, index < servers.size() - 1);
                        serverCell.setColors(
                            server.enabled ? Theme.key_windowBackgroundWhiteBlackText : Theme.key_windowBackgroundWhiteGrayText,
                            Theme.key_windowBackgroundWhiteGrayText2
                        );
                    }
                    break;
                case 4: // Info
                    TextInfoPrivacyCell infoCell = (TextInfoPrivacyCell) holder.itemView;
                    if (position == serverModeInfoRow) {
                        infoCell.setText(LocaleController.getString("CallServerModeInfo", R.string.CallServerModeInfo));
                        infoCell.setBackgroundDrawable(Theme.getThemedDrawableByKey(mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                    } else if (position == settingsInfoRow) {
                        infoCell.setText(LocaleController.getString("CallSettingsInfo", R.string.CallSettingsInfo));
                        infoCell.setBackgroundDrawable(Theme.getThemedDrawableByKey(mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                    } else if (position == turnServersInfoRow) {
                        infoCell.setText(LocaleController.getString("TurnServersInfo", R.string.TurnServersInfo));
                        infoCell.setBackgroundDrawable(Theme.getThemedDrawableByKey(mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                    }
                    break;
            }
        }

        @Override
        public int getItemViewType(int position) {
            if (position == serverModeHeaderRow || position == settingsHeaderRow || position == turnServersHeaderRow) {
                return 0; // Header
            } else if (position == addTurnServerRow || position == shareSettingsRow || position == importSettingsRow 
                    || position == callServerUrlRow || position == checkTariffRow || position == tariffInfoRow) {
                return 1; // TextCell
            } else if (position == useCallServerRow || position == forceWebRTCRow || position == useTCPRow 
                    || position == disableP2PRow || position == replaceStandardRow) {
                return 2; // TextCheckCell
            } else if (position >= turnServersStartRow && position < turnServersEndRow) {
                return 3; // Turn server
            } else {
                return 4; // Info
            }
        }
    }

    private void importSettingsFromClipboard() {
        Context context = getParentActivity();
        if (context == null) return;
        
        android.content.ClipboardManager clipboard = (android.content.ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null || !clipboard.hasPrimaryClip()) {
            BulletinFactory.of(this).createErrorBulletin(
                LocaleController.getString("ClipboardEmpty", R.string.ClipboardEmpty)
            ).show();
            return;
        }
        
        android.content.ClipData clip = clipboard.getPrimaryClip();
        if (clip == null || clip.getItemCount() == 0) {
            BulletinFactory.of(this).createErrorBulletin(
                LocaleController.getString("ClipboardEmpty", R.string.ClipboardEmpty)
            ).show();
            return;
        }
        
        CharSequence text = clip.getItemAt(0).getText();
        if (text == null || !CallSettingsManager.isCallSettingsMessage(text.toString())) {
            BulletinFactory.of(this).createErrorBulletin(
                LocaleController.getString("NoCallSettingsInClipboard", R.string.NoCallSettingsInClipboard)
            ).show();
            return;
        }
        
        // Show confirmation dialog
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(LocaleController.getString("ImportCallSettings", R.string.ImportCallSettings));
        
        String summary = CallSettingsManager.getSettingsSummary(text.toString());
        builder.setMessage(summary != null ? summary : text.toString());
        
        builder.setPositiveButton(LocaleController.getString("Import", R.string.Import), (dialog, which) -> {
            if (CallSettingsManager.getInstance().importSettingsFromMessage(text.toString())) {
                updateRows();
                if (listAdapter != null) {
                    listAdapter.notifyDataSetChanged();
                }
                BulletinFactory.of(this).createSuccessBulletin(
                    LocaleController.getString("CallSettingsApplied", R.string.CallSettingsApplied)
                ).show();
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.show();
    }
    
    private void showCallServerUrlDialog() {
        Context context = getParentActivity();
        if (context == null) return;
        
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(LocaleController.getString("CallServerUrl", R.string.CallServerUrl));
        
        final EditText input = new EditText(context);
        input.setHint("https://example.com/api");
        input.setText(CallSettingsManager.getInstance().getCallServerUrl());
        input.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_URI);
        input.setSelection(input.getText().length());
        
        FrameLayout container = new FrameLayout(context);
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.WRAP_CONTENT
        );
        params.leftMargin = AndroidUtilities.dp(24);
        params.rightMargin = AndroidUtilities.dp(24);
        input.setLayoutParams(params);
        container.addView(input);
        builder.setView(container);
        
        builder.setPositiveButton(LocaleController.getString("Save", R.string.Save), (dialog, which) -> {
            String url = input.getText().toString().trim();
            CallSettingsManager.getInstance().setCallServerUrl(url);
            if (listAdapter != null) {
                listAdapter.notifyDataSetChanged();
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.show();
    }
    
    private void checkTariff() {
        Context context = getParentActivity();
        if (context == null) return;
        
        String serverUrl = CallSettingsManager.getInstance().getCallServerUrl();
        if (serverUrl == null || serverUrl.isEmpty()) {
            BulletinFactory.of(this).createErrorBulletin(
                LocaleController.getString("CallServerUrlNotSet", R.string.CallServerUrlNotSet)
            ).show();
            return;
        }
        
        // Show loading
        AlertDialog progressDialog = new AlertDialog(context, AlertDialog.ALERT_TYPE_SPINNER);
        progressDialog.setCanCancel(false);
        progressDialog.show();
        
        CallServerManager.getInstance().queryTariff(new CallServerManager.TariffCallback() {
            @Override
            public void onSuccess(CallServerManager.TariffResponse response) {
                progressDialog.dismiss();
                showTariffInfo(response);
            }
            
            @Override
            public void onError(String error) {
                progressDialog.dismiss();
                BulletinFactory.of(AdvancedCallSettingsActivity.this).createErrorBulletin(error).show();
            }
        });
    }
    
    private void showTariffInfo(CallServerManager.TariffResponse response) {
        Context context = getParentActivity();
        if (context == null) return;
        
        StringBuilder message = new StringBuilder();
        message.append(LocaleController.getString("Tariff", R.string.Tariff)).append(": ");
        message.append(response.tariff).append("\n\n");
        
        if (CallServerManager.TARIFF_FREE.equals(response.tariff) && response.freeMinutesRemaining >= 0) {
            message.append(LocaleController.getString("FreeMinutesRemaining", R.string.FreeMinutesRemaining)).append(": ");
            message.append(String.format("%.1f", response.freeMinutesRemaining)).append("\n\n");
        }
        
        if (response.periodEnd != null && !response.periodEnd.isEmpty()) {
            message.append(LocaleController.getString("PeriodEnd", R.string.PeriodEnd)).append(": ");
            message.append(response.periodEnd);
        }
        
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(LocaleController.getString("TariffInfo", R.string.TariffInfo));
        builder.setMessage(message.toString());
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        builder.show();
    }
    
    private void shareSettings() {
        Context context = getParentActivity();
        if (context == null) return;
        
        String settingsText = CallSettingsManager.getInstance().exportSettingsForSharing();
        if (settingsText == null) {
            return;
        }
        
        // Copy to clipboard
        android.content.ClipboardManager clipboard = (android.content.ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null) {
            android.content.ClipData clip = android.content.ClipData.newPlainText("Call Settings", settingsText);
            clipboard.setPrimaryClip(clip);
            
            BulletinFactory.of(this).createCopyBulletin(
                LocaleController.getString("CallSettingsCopied", R.string.CallSettingsCopied)
            ).show();
        }
    }
    
    @Override
    public ArrayList<ThemeDescription> getThemeDescriptions() {
        ArrayList<ThemeDescription> themeDescriptions = new ArrayList<>();
        themeDescriptions.add(new ThemeDescription(listView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray));
        themeDescriptions.add(new ThemeDescription(actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault));
        return themeDescriptions;
    }
}

