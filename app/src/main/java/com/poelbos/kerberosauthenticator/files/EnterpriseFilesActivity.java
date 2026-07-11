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
import com.poelbos.kerberosauthenticator.R;
import com.poelbos.kerberosauthenticator.databinding.ActivityEnterpriseFilesBinding;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.io.File;
import java.io.InputStream;
import java.net.URLConnection;

/** Focused enterprise file browser. Shares can only originate from managed configuration. */
public final class EnterpriseFilesActivity extends AppCompatActivity {
  private ActivityEnterpriseFilesBinding binding;
  private EnterpriseConfiguration configuration;
  private KerberosSmbClient smbClient;
  private ManagedShare currentShare;
  private String currentPath = "";
  private final ExecutorService io = Executors.newSingleThreadExecutor();
  private ActivityResultLauncher<String[]> uploadLauncher;

  @Override protected void onCreate(Bundle state) {
    super.onCreate(state);
    binding = ActivityEnterpriseFilesBinding.inflate(getLayoutInflater());
    setContentView(binding.getRoot());
    binding.list.setLayoutManager(new LinearLayoutManager(this));
    binding.signInButton.setOnClickListener(view ->
        startActivity(new Intent(this, AuthenticatorStatusActivity.class)));
    binding.backButton.setOnClickListener(view -> navigateBack());
    binding.createFolderButton.setOnClickListener(view -> promptCreateFolder());
    binding.uploadButton.setOnClickListener(view -> uploadLauncher.launch(new String[] {"*/*"}));
    uploadLauncher = registerForActivityResult(new ActivityResultContracts.OpenDocument(), this::uploadDocument);
    getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
      @Override public void handleOnBackPressed() {
        if (currentShare == null) finish(); else navigateBack();
      }
    });
  }

  @Override protected void onResume() {
    super.onResume();
    EnterpriseConfiguration updated = EnterpriseConfiguration.from(this);
    if (!updated.isAllowScreenshots()) {
      getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    } else {
      getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }
    if (configuration == null || !configuration.getShares().equals(updated.getShares())) {
      closeSession();
      currentShare = null;
      currentPath = "";
    }
    configuration = updated;
    showOverview();
  }

  private void showOverview() {
    binding.title.setText("Bedrijfsbestanden");
    binding.backButton.setVisibility(View.GONE);
    binding.createFolderButton.setVisibility(View.GONE);
    binding.uploadButton.setVisibility(View.GONE);
    KerberosAccount account = KerberosAccount.getAccount(this);
    binding.subtitle.setText(account == null
        ? "Veilig verbonden met uw werkomgeving"
        : account.getName() + "  •  Kerberos beveiligd");
    binding.signInButton.setText(account == null ? "Aanmelden" : "Account");
    if (!configuration.isValid()) {
      showState("Configuratie nodig", String.join("\n", configuration.getErrors()), false);
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
      Snackbar.make(binding.root, "Meld u eerst aan met uw werkaccount", Snackbar.LENGTH_LONG)
          .setAction("Aanmelden", view ->
              startActivity(new Intent(this, AuthenticatorStatusActivity.class))).show();
      return;
    }
    closeSession();
    currentShare = managedShare;
    currentPath = "";
    binding.backButton.setVisibility(View.VISIBLE);
    binding.createFolderButton.setVisibility(View.VISIBLE);
    binding.uploadButton.setVisibility(View.VISIBLE);
    loadDirectory();
  }

  private void loadDirectory() {
    binding.title.setText(currentShare.getDisplayName());
    binding.subtitle.setText(currentPath.isEmpty() ? "Hoofdmap" : currentPath.replace("\\", " › "));
    showState("Even geduld", "De beveiligde map wordt geopend…", true);
    io.execute(() -> {
      try {
        if (smbClient == null) {
          smbClient = KerberosSmbClient.connect(
              KerberosAccount.getAccount(this), currentShare,
              configuration.isRequireEncryption());
        }
        List<RemoteEntry> entries = smbClient.list(currentPath);
        List<Row> rows = new ArrayList<>();
        for (RemoteEntry entry : entries) rows.add(Row.forEntry(entry));
        runOnUiThread(() -> {
          if (rows.isEmpty()) showState("Deze map is leeg", "Hier staan nog geen bestanden.", false);
          else showRows(rows);
        });
      } catch (Exception exception) {
        runOnUiThread(() -> showState(
            "Kan de map niet openen", friendlyMessage(exception), false));
      }
    });
  }

  private static String friendlyMessage(Exception exception) {
    String message = exception.getMessage();
    if (message == null || message.trim().isEmpty()) return "Controleer uw netwerk en probeer opnieuw.";
    return message + "\n\nControleer uw VPN, tijdinstelling en werkaccount.";
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
          "Openen is door uw beheerder uitgeschakeld omdat lokale cache niet is toegestaan.",
          Snackbar.LENGTH_LONG).show();
      return;
    }
    showState("Bestand voorbereiden", "Het bestand wordt beveiligd opgehaald…", true);
    final String path = KerberosSmbClient.join(currentPath, entry.getName());
    io.execute(() -> {
      try {
        File directory = new File(getCacheDir(), "opened");
        File local = new File(directory, currentShare.getId() + "-" + safeName(entry.getName()));
        smbClient.download(path, local);
        Uri uri = FileProvider.getUriForFile(this, getPackageName() + ".files", local);
        String mime = URLConnection.guessContentTypeFromName(entry.getName());
        Intent intent = new Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, mime == null ? "application/octet-stream" : mime)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        runOnUiThread(() -> {
          loadDirectory();
          try { startActivity(Intent.createChooser(intent, "Openen met")); }
          catch (Exception exception) {
            Snackbar.make(binding.root, "Geen geschikte app gevonden", Snackbar.LENGTH_LONG).show();
          }
        });
      } catch (Exception exception) {
        runOnUiThread(() -> showState("Bestand kan niet worden geopend", friendlyMessage(exception), false));
      }
    });
  }

  private static String safeName(String name) {
    return name.replaceAll("[^A-Za-z0-9._ -]", "_");
  }

  private void navigateBack() {
    if (currentShare == null) return;
    if (!currentPath.isEmpty()) {
      int separator = currentPath.lastIndexOf('\\');
      currentPath = separator < 0 ? "" : currentPath.substring(0, separator);
      loadDirectory();
      return;
    }
    closeSession();
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

  private void closeSession() {
    if (smbClient != null) smbClient.close();
    smbClient = null;
  }

  private void promptCreateFolder() {
    TextInputEditText input = new TextInputEditText(this);
    input.setHint("Mapnaam");
    int padding = (int) (24 * getResources().getDisplayMetrics().density);
    input.setPadding(padding, padding / 2, padding, 0);
    new MaterialAlertDialogBuilder(this)
        .setTitle("Nieuwe map")
        .setView(input)
        .setNegativeButton("Annuleren", null)
        .setPositiveButton("Maken", (dialog, which) -> runOperation("Map maken", () ->
            smbClient.createDirectory(currentPath, String.valueOf(input.getText()))))
        .show();
  }

  private void uploadDocument(Uri uri) {
    if (uri == null || currentShare == null) return;
    String name = queryDisplayName(uri);
    runOperation("Uploaden", () -> {
      try (InputStream input = getContentResolver().openInputStream(uri)) {
        if (input == null) throw new IllegalStateException("Bestand kan niet worden gelezen");
        smbClient.upload(KerberosSmbClient.join(currentPath, name), input);
      }
    });
  }

  private String queryDisplayName(Uri uri) {
    try (android.database.Cursor cursor = getContentResolver().query(
        uri, new String[] {android.provider.OpenableColumns.DISPLAY_NAME}, null, null, null)) {
      if (cursor != null && cursor.moveToFirst()) return cursor.getString(0);
    }
    String segment = uri.getLastPathSegment();
    return segment == null ? "upload" : safeName(segment);
  }

  private void showEntryActions(Row row) {
    if (row.entry == null) return;
    new MaterialAlertDialogBuilder(this)
        .setTitle(row.entry.getName())
        .setItems(new String[] {"Hernoemen", "Verwijderen"}, (dialog, which) -> {
          if (which == 0) promptRename(row.entry); else confirmDelete(row.entry);
        }).show();
  }

  private void promptRename(RemoteEntry entry) {
    TextInputEditText input = new TextInputEditText(this);
    input.setText(entry.getName());
    input.selectAll();
    int padding = (int) (24 * getResources().getDisplayMetrics().density);
    input.setPadding(padding, padding / 2, padding, 0);
    new MaterialAlertDialogBuilder(this).setTitle("Hernoemen").setView(input)
        .setNegativeButton("Annuleren", null)
        .setPositiveButton("Opslaan", (dialog, which) -> runOperation("Hernoemen", () ->
            smbClient.rename(KerberosSmbClient.join(currentPath, entry.getName()),
                String.valueOf(input.getText())))).show();
  }

  private void confirmDelete(RemoteEntry entry) {
    new MaterialAlertDialogBuilder(this)
        .setTitle("Definitief verwijderen?")
        .setMessage(entry.isDirectory()
            ? "De map en alle inhoud worden van de bedrijfsshare verwijderd."
            : "Het bestand wordt van de bedrijfsshare verwijderd.")
        .setNegativeButton("Annuleren", null)
        .setPositiveButton("Verwijderen", (dialog, which) -> runOperation("Verwijderen", () ->
            smbClient.delete(KerberosSmbClient.join(currentPath, entry.getName()), entry.isDirectory())))
        .show();
  }

  private void runOperation(String label, ThrowingOperation operation) {
    showState(label, "Even geduld…", true);
    io.execute(() -> {
      try {
        operation.run();
        runOnUiThread(this::loadDirectory);
      } catch (Exception exception) {
        runOnUiThread(() -> showState(label + " is mislukt", friendlyMessage(exception), false));
      }
    });
  }

  private interface ThrowingOperation { void run() throws Exception; }

  @Override protected void onDestroy() {
    closeSession();
    io.shutdownNow();
    super.onDestroy();
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
        holder.detail.setText(row.entry.isDirectory() ? "Map" : formatSize(row.entry.getSize()));
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
      if (bytes < 1024L * 1024L) return String.format("%.1f KB", bytes / 1024.0);
      if (bytes < 1024L * 1024L * 1024L) return String.format("%.1f MB", bytes / 1048576.0);
      return String.format("%.1f GB", bytes / 1073741824.0);
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
