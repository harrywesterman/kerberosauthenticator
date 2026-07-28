package com.poelbos.kerberosauthenticator.files;

import android.content.Intent;
import android.os.Bundle;
import android.net.Uri;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.TextView;
import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.FileProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.textfield.TextInputEditText;
import com.poelbos.kerberosauthenticator.AuthenticatorStatusActivity;
import com.poelbos.kerberosauthenticator.KerberosAccount;
import com.poelbos.kerberosauthenticator.LoginActivity;
import com.poelbos.kerberosauthenticator.R;
import com.poelbos.kerberosauthenticator.SystemBarInsets;
import com.poelbos.kerberosauthenticator.databinding.ActivityEnterpriseFilesBinding;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.io.File;
import java.io.InputStream;
import java.net.URLConnection;

/** Focused enterprise file browser. Shares can only originate from managed configuration. */
public final class EnterpriseFilesActivity extends AppCompatActivity {
  private static final String STATE_ACCOUNT_SIGN_IN_OFFERED = "account_sign_in_offered";

  private ActivityEnterpriseFilesBinding binding;
  private EnterpriseConfiguration configuration;
  private KerberosSmbClient smbClient;
  private ManagedShare currentShare;
  private String currentPath = "";
  private final ExecutorService io = Executors.newSingleThreadExecutor();
  private ActivityResultLauncher<String[]> uploadLauncher;
  private ActivityResultLauncher<Intent> viewerLauncher;
  private EnterpriseFileCache fileCache;
  private volatile long generation;
  private volatile boolean destroyed;
  private File pendingViewedFile;
  private Uri pendingViewedUri;
  private boolean accountSignInOffered;

  @Override protected void onCreate(Bundle state) {
    super.onCreate(state);
    accountSignInOffered =
        state != null && state.getBoolean(STATE_ACCOUNT_SIGN_IN_OFFERED, false);
    fileCache = new EnterpriseFileCache(this);
    fileCache.cleanup();
    binding = ActivityEnterpriseFilesBinding.inflate(getLayoutInflater());
    setContentView(binding.getRoot());
    SystemBarInsets.applyToTopAppBar(binding.topAppBar);
    binding.list.setLayoutManager(new LinearLayoutManager(this));
    binding.topAppBar.setOnMenuItemClickListener(item -> {
      if (item.getItemId() == R.id.action_account) {
        startActivity(new Intent(this, AuthenticatorStatusActivity.class));
        return true;
      }
      return false;
    });
    binding.backButton.setOnClickListener(view -> navigateBack());
    binding.createFolderButton.setOnClickListener(view -> promptCreateFolder());
    binding.uploadButton.setOnClickListener(view -> uploadLauncher.launch(new String[] {"*/*"}));
    uploadLauncher = registerForActivityResult(new ActivityResultContracts.OpenDocument(), this::uploadDocument);
    viewerLauncher = registerForActivityResult(
        new ActivityResultContracts.StartActivityForResult(), ignored -> clearPendingViewedFile());
    getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
      @Override public void handleOnBackPressed() {
        if (currentShare == null) finish(); else navigateBack();
      }
    });
  }

  @Override protected void onSaveInstanceState(@NonNull Bundle outState) {
    outState.putBoolean(STATE_ACCOUNT_SIGN_IN_OFFERED, accountSignInOffered);
    super.onSaveInstanceState(outState);
  }

  @Override protected void onResume() {
    super.onResume();
    EnterpriseConfiguration updated = EnterpriseConfiguration.from(this);
    if (!updated.isAllowCache()) fileCache.cleanup();
    if (!updated.isAllowScreenshots()) {
      getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    } else {
      getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }
    if (configuration == null || sessionPolicyChanged(configuration, updated)) {
      invalidateSession();
      fileCache.cleanup();
      currentShare = null;
      currentPath = "";
    }
    configuration = updated;
    KerberosAccount account = KerberosAccount.getAccount(this);
    if (account != null && (updated.getRealm().isEmpty()
        || !account.getDomain().equalsIgnoreCase(updated.getRealm()))) {
      KerberosAccount.removeAccount(this);
      invalidateSession();
      fileCache.cleanup();
    }
    if (!accountSignInOffered && KerberosAccount.getAccount(this) == null
        && !configuration.getRealm().isEmpty()) {
      accountSignInOffered = true;
      startActivity(LoginActivity.getAccountSignInIntent(this));
      return;
    }
    if (currentShare == null) showOverview(); else loadDirectory();
  }

  private void showOverview() {
    binding.topAppBar.setTitle(R.string.enterprise_files);
    binding.backButton.setVisibility(View.GONE);
    binding.createFolderButton.setVisibility(View.GONE);
    binding.uploadButton.setVisibility(View.GONE);
    KerberosAccount account = KerberosAccount.getAccount(this);
    binding.subtitle.setText(account == null
        ? "Securely connected to your work environment"
        : account.getName() + "  •  Kerberos secured");
    if (!configuration.isValid()) {
      showState("Configuration required", String.join("\n", configuration.getErrors()), false);
      return;
    }
    List<Row> rows = new ArrayList<>();
    for (ManagedShare share : configuration.getShares()) {
      rows.add(Row.forShare(share));
    }
    showRows(rows);
  }

  private void openShare(ManagedShare managedShare) {
    if (KerberosAccount.getAccount(this) == null) {
      Snackbar.make(binding.root, "Sign in with your work account first", Snackbar.LENGTH_LONG)
          .setAction("Sign in", view ->
              startActivity(new Intent(this, AuthenticatorStatusActivity.class))).show();
      return;
    }
    invalidateSession();
    currentShare = managedShare;
    currentPath = "";
    binding.backButton.setVisibility(View.VISIBLE);
    binding.createFolderButton.setVisibility(View.VISIBLE);
    binding.uploadButton.setVisibility(View.VISIBLE);
    loadDirectory();
  }

  private void loadDirectory() {
    final ManagedShare shareSnapshot = currentShare;
    final String pathSnapshot = currentPath;
    final EnterpriseConfiguration configurationSnapshot = configuration;
    final KerberosAccount accountSnapshot = KerberosAccount.getAccount(this);
    final long requestGeneration = ++generation;
    if (shareSnapshot == null || configurationSnapshot == null) return;
    binding.topAppBar.setTitle(shareSnapshot.getDisplayName());
    binding.subtitle.setText(pathSnapshot.isEmpty() ? "Root folder" : pathSnapshot.replace("\\", " › "));
    showState("Please wait", "The secure folder is being opened…", true);
    io.execute(() -> {
      try {
        if (smbClient == null) {
          smbClient = KerberosSmbClient.connect(
              getApplicationContext(), accountSnapshot, shareSnapshot,
              configurationSnapshot.isRequireEncryption());
        }
        List<RemoteEntry> entries = smbClient.list(pathSnapshot);
        List<Row> rows = new ArrayList<>();
        for (RemoteEntry entry : entries) rows.add(Row.forEntry(entry));
        postIfCurrent(requestGeneration, () -> {
          if (rows.isEmpty()) showState("This folder is empty", "There are no files here yet.", false);
          else showRows(rows);
        });
      } catch (Exception exception) {
        postIfCurrent(requestGeneration, () -> showState(
            "Unable to open the folder", friendlyMessage(exception), false));
      }
    });
  }

  private static String friendlyMessage(Exception exception) {
    String message = exception.getMessage();
    if (message == null || message.trim().isEmpty()) return "Check your network and try again.";
    return message + "\n\nCheck your VPN, time settings, and work account.";
  }

  private void onRowClicked(Row row) {
    if (row.share != null) {
      openShare(row.share);
    } else if (row.entry != null && row.entry.isDirectory()) {
      currentPath = KerberosSmbClient.join(currentPath, row.entry.getName());
      loadDirectory();
    } else {
      openFile(row.entry);
    }
  }

  private void openFile(RemoteEntry entry) {
    if (!configuration.isAllowCache()) {
      Snackbar.make(binding.root,
          "Opening is disabled by your administrator because local caching is not allowed.",
          Snackbar.LENGTH_LONG).show();
      return;
    }
    showState("Preparing file", "The file is being securely downloaded…", true);
    final String path = KerberosSmbClient.join(currentPath, entry.getName());
    final ManagedShare shareSnapshot = currentShare;
    final long requestGeneration = ++generation;
    io.execute(() -> {
      try {
        if (smbClient == null || shareSnapshot == null) {
          throw new IllegalStateException("The secure share is no longer open");
        }
        File local = fileCache.create(shareSnapshot.getId(), entry.getName());
        smbClient.download(path, local);
        Uri uri = FileProvider.getUriForFile(this, getPackageName() + ".files", local);
        String mime = URLConnection.guessContentTypeFromName(entry.getName());
        Intent intent = new Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, mime == null ? "application/octet-stream" : mime)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        postIfCurrent(requestGeneration, () -> {
          pendingViewedFile = local;
          pendingViewedUri = uri;
          try { viewerLauncher.launch(Intent.createChooser(intent, "Open with")); }
          catch (Exception exception) {
            clearPendingViewedFile();
            Snackbar.make(binding.root, "No suitable app found", Snackbar.LENGTH_LONG).show();
          }
        });
      } catch (Exception exception) {
        postIfCurrent(requestGeneration,
            () -> showState("Unable to open file", friendlyMessage(exception), false));
      }
    });
  }

  private void navigateBack() {
    if (currentShare == null) return;
    if (!currentPath.isEmpty()) {
      int separator = currentPath.lastIndexOf('\\');
      currentPath = separator < 0 ? "" : currentPath.substring(0, separator);
      loadDirectory();
      return;
    }
    invalidateSession();
    currentShare = null;
    showOverview();
  }

  private void showRows(List<Row> rows) {
    binding.emptyState.setVisibility(View.GONE);
    binding.list.setVisibility(View.VISIBLE);
    binding.list.setAdapter(new RowAdapter(rows, this::onRowClicked, this::showEntryActions));
  }

  private void showState(String title, String message, boolean progress) {
    binding.list.setVisibility(View.GONE);
    binding.emptyState.setVisibility(View.VISIBLE);
    binding.progress.setVisibility(progress ? View.VISIBLE : View.GONE);
    binding.emptyTitle.setText(title);
    binding.emptyMessage.setText(message);
  }

  private void promptCreateFolder() {
    TextInputEditText input = new TextInputEditText(this);
    input.setHint("Folder name");
    int padding = (int) (24 * getResources().getDisplayMetrics().density);
    input.setPadding(padding, padding / 2, padding, 0);
    new MaterialAlertDialogBuilder(this)
        .setTitle("New folder")
        .setView(input)
        .setNegativeButton("Cancel", null)
        .setPositiveButton("Create", (dialog, which) -> {
          String parent = currentPath;
          String name = String.valueOf(input.getText());
          runOperation("Create folder", () -> smbClient.createDirectory(parent, name));
        })
        .show();
  }

  private void uploadDocument(Uri uri) {
    if (uri == null || currentShare == null) return;
    String name = queryDisplayName(uri);
    String target = KerberosSmbClient.join(currentPath, name);
    runOperation("Uploaden", () -> {
      try (InputStream input = getContentResolver().openInputStream(uri)) {
        if (input == null) throw new IllegalStateException("Unable to read the file");
        smbClient.upload(target, input);
      }
    });
  }

  private String queryDisplayName(Uri uri) {
    try (android.database.Cursor cursor = getContentResolver().query(
        uri, new String[] {android.provider.OpenableColumns.DISPLAY_NAME}, null, null, null)) {
      if (cursor != null && cursor.moveToFirst()) return cursor.getString(0);
    }
    String segment = uri.getLastPathSegment();
    return segment == null ? "upload" : EnterpriseFileCache.safeName(segment);
  }

  private void showEntryActions(Row row) {
    if (row.entry == null) return;
    new MaterialAlertDialogBuilder(this)
        .setTitle(row.entry.getName())
        .setItems(new String[] {"Rename", "Delete"}, (dialog, which) -> {
          if (which == 0) promptRename(row.entry); else confirmDelete(row.entry);
        }).show();
  }

  private void promptRename(RemoteEntry entry) {
    TextInputEditText input = new TextInputEditText(this);
    input.setText(entry.getName());
    input.selectAll();
    int padding = (int) (24 * getResources().getDisplayMetrics().density);
    input.setPadding(padding, padding / 2, padding, 0);
    new MaterialAlertDialogBuilder(this).setTitle("Rename").setView(input)
        .setNegativeButton("Cancel", null)
        .setPositiveButton("Save", (dialog, which) -> {
          String source = KerberosSmbClient.join(currentPath, entry.getName());
          String newName = String.valueOf(input.getText());
          runOperation("Rename", () -> smbClient.rename(source, newName));
        }).show();
  }

  private void confirmDelete(RemoteEntry entry) {
    new MaterialAlertDialogBuilder(this)
        .setTitle("Delete permanently?")
        .setMessage(entry.isDirectory()
            ? "The folder and all its contents will be deleted from the enterprise share."
            : "The file will be deleted from the enterprise share.")
        .setNegativeButton("Cancel", null)
        .setPositiveButton("Delete", (dialog, which) -> {
          String target = KerberosSmbClient.join(currentPath, entry.getName());
          runOperation("Delete", () -> smbClient.delete(target, entry.isDirectory()));
        })
        .show();
  }

  private void runOperation(String label, ThrowingOperation operation) {
    final long requestGeneration = ++generation;
    showState(label, "Please wait…", true);
    io.execute(() -> {
      try {
        operation.run();
        postIfCurrent(requestGeneration, this::loadDirectory);
      } catch (Exception exception) {
        postIfCurrent(requestGeneration,
            () -> showState(label + " failed", friendlyMessage(exception), false));
      }
    });
  }

  private interface ThrowingOperation { void run() throws Exception; }

  @Override protected void onDestroy() {
    destroyed = true;
    generation++;
    try {
      io.execute(this::closeSessionOnIoThread);
    } catch (RejectedExecutionException ignored) {}
    io.shutdown();
    super.onDestroy();
  }

  private void invalidateSession() {
    generation++;
    try {
      io.execute(this::closeSessionOnIoThread);
    } catch (RejectedExecutionException ignored) {}
  }

  private void closeSessionOnIoThread() {
    if (smbClient != null) smbClient.close();
    smbClient = null;
  }

  private void postIfCurrent(long requestGeneration, Runnable action) {
    runOnUiThread(() -> {
      if (!destroyed && generation == requestGeneration) action.run();
    });
  }

  private void clearPendingViewedFile() {
    if (pendingViewedUri != null) revokeUriPermission(
        pendingViewedUri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
    fileCache.delete(pendingViewedFile);
    pendingViewedUri = null;
    pendingViewedFile = null;
    if (!destroyed && currentShare != null) loadDirectory();
  }

  private static boolean sessionPolicyChanged(
      EnterpriseConfiguration previous, EnterpriseConfiguration updated) {
    return !previous.getRealm().equals(updated.getRealm())
        || !previous.getShares().equals(updated.getShares())
        || previous.isRequireEncryption() != updated.isRequireEncryption()
        || previous.isAllowCache() != updated.isAllowCache();
  }

  private interface ClickListener { void onClick(Row row); }

  private static final class Row {
    final ManagedShare share;
    final RemoteEntry entry;
    private Row(ManagedShare share, RemoteEntry entry) { this.share = share; this.entry = entry; }
    static Row forShare(ManagedShare share) { return new Row(share, null); }
    static Row forEntry(RemoteEntry entry) { return new Row(null, entry); }
  }

  private static final class RowAdapter extends RecyclerView.Adapter<RowAdapter.Holder> {
    private final List<Row> rows;
    private final ClickListener listener;
    private final ClickListener longClickListener;
    RowAdapter(List<Row> rows, ClickListener listener, ClickListener longClickListener) {
      this.rows = rows; this.listener = listener; this.longClickListener = longClickListener;
    }
    @NonNull @Override public Holder onCreateViewHolder(@NonNull ViewGroup parent, int type) {
      return new Holder(LayoutInflater.from(parent.getContext())
          .inflate(R.layout.item_enterprise_file, parent, false));
    }
    @Override public void onBindViewHolder(@NonNull Holder holder, int position) {
      Row row = rows.get(position);
      if (row.share != null) {
        holder.icon.setText("▣");
        holder.name.setText(row.share.getDisplayName());
        holder.detail.setText(row.share.getHost() + "  •  Kerberos");
      } else {
        holder.icon.setText(row.entry.isDirectory() ? "◆" : "▪");
        holder.name.setText(row.entry.getName());
        holder.detail.setText(row.entry.isDirectory() ? "Folder" : formatSize(row.entry.getSize()));
      }
      holder.itemView.setContentDescription(holder.name.getText() + ", " + holder.detail.getText());
      holder.itemView.setOnClickListener(view -> listener.onClick(row));
      holder.itemView.setOnLongClickListener(view -> {
        if (row.entry == null) return false;
        longClickListener.onClick(row);
        return true;
      });
    }
    @Override public int getItemCount() { return rows.size(); }
    private static String formatSize(long bytes) {
      if (bytes < 1024) return bytes + " B";
      if (bytes < 1024L * 1024L) {
        return String.format(Locale.ROOT, "%.1f KB", bytes / 1024.0);
      }
      if (bytes < 1024L * 1024L * 1024L) {
        return String.format(Locale.ROOT, "%.1f MB", bytes / 1048576.0);
      }
      return String.format(Locale.ROOT, "%.1f GB", bytes / 1073741824.0);
    }
    static final class Holder extends RecyclerView.ViewHolder {
      final TextView icon;
      final TextView name;
      final TextView detail;
      Holder(View view) {
        super(view);
        icon = view.findViewById(R.id.icon);
        name = view.findViewById(R.id.name);
        detail = view.findViewById(R.id.detail);
      }
    }
  }
}
