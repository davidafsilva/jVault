package pt.davidafsilva.jvault.vault;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Mac;

import pt.davidafsilva.jvault.model.SecureEntry;
import pt.davidafsilva.jvault.model.UnsecureEntry;

/**
 * An abstract file vault implementation that shall be reused by it's concrete file
 * implementations.
 *
 * @author David Silva
 */
abstract class AbstractFileVault<S extends OutputStream> implements FileVault {

  // logger
  private static final Logger log = LoggerFactory.getLogger(AbstractFileVault.class);

  // the MAC algorithm
  private static final String MAC_ALGORITHM = "HmacSHA256";

  // the change flag
  private final AtomicBoolean changed;

  // the path/file name
  private final Path path;

  // the backed in-memory vault
  final InMemoryVault inMemoryVault;

  /**
   * Creates a vault with the specified parameters.
   *
   * @param password   the vaults password for PBE
   * @param salt       the salt (should be a random) to protect against dictionary attacks
   * @param iterations the number of iterations to be applied when deriving the actual cipher key
   * @param keyLength  the size of the key to be used for encryption (affects the salt size asl
   *                   well)
   * @param path       the path of the vault file
   * @throws VaultInitializationException if an error occurs while initializing the vault
   */
  AbstractFileVault(final String password, final String salt, final int iterations,
                    final int keyLength, final Path path) throws VaultInitializationException {
    this(password.toCharArray(), salt.getBytes(Vault.VAULT_CS),
         iterations, keyLength, path);
  }

  /**
   * Creates a vault with the specified parameters.
   *
   * @param password   the vaults password for PBE
   * @param salt       the salt (should be a random) to protect against dictionary attacks
   * @param iterations the number of iterations to be applied when deriving the actual cipher key
   * @param keyLength  the size of the key to be used for encryption (affects the salt size asl
   *                   well)
   * @param path       the path of the vault file
   * @throws VaultInitializationException if an error occurs while initializing the vault
   */
  AbstractFileVault(final char[] password, final byte[] salt, final int iterations,
                    final int keyLength, final Path path) throws VaultInitializationException {
    this.path = path;
    final File fp = path.toFile();
    if (fp.exists() && (!fp.isFile() || !fp.canRead())) {
      throw new VaultInitializationException(
          "Invalid vault file, not a file or no read permissions");
    } else if (!fp.canWrite()) {
      throw new VaultInitializationException(
          "Invalid vault file, no write permissions");
    }
    inMemoryVault = new InMemoryVault(password, salt, iterations, keyLength);
    changed = new AtomicBoolean(false);
    // initialize the vault
    load();
  }

  /**
   * Loads the vault file contents.
   *
   * @throws VaultInitializationException if the any of the security settings are not supported or
   *                                      an invalid key is used.
   */
  private void load() throws VaultInitializationException {
    try {
      log.info("initializing the vault from file..");
      final File fp = path.toFile();
      // check the file
      if (fp.exists() && fp.canRead() && fp.isFile()) {
        // read the data
        final byte[] data = Files.readAllBytes(path);
        if (data.length > 0) {
          buildVaultFromData(data);
          log.info("vault successfully loaded");
        } else {
          log.info("no entries in the vault.");
        }
      } else if (fp.exists()) {
        log.error("unable to read the vault file");
        throw new IOException("Unable to read the vault file");
      } else {
        log.info("no file for loading, skipping load.");
      }
    } catch (final IOException ioe) {
      log.error("I/O error", ioe);
      throw new VaultInitializationException("Unable to load vault file", ioe);
    }
  }

  /**
   * Builds the vault from the given data, previously read from the file
   *
   * @param data the file data
   * @throws VaultCorruptedException if the data is corrupted
   */
  abstract void buildVaultFromData(final byte[] data)
      throws VaultCorruptedException, VaultInitializationException;

  /**
   * Throws an {@link VaultCorruptedException} denoting that the data read is somehow corrupted and
   * we're unable to properly restore the vault.
   *
   * @throws VaultCorruptedException with a generic corruption message
   */
  void vaultCorrupted() {
    throw new VaultCorruptedException("vault structured is corrupted");
  }

  /**
   * {@inheritDoc}
   *
   * This implementation ignores concurrent calls to this method, adhering to
   */
  @Override
  public void persist() throws IOException, VaultOperationException {
    if (changed.compareAndSet(true, false)) {
      final Collection<InMemoryVault.SecureEntryWrapper> values = inMemoryVault.map.values();
      try (final S stream = createStream(path)) {
        writeHeader(stream, values);
        writeMac(stream, calculateMAC(values));
        writeEntries(stream, values);
        writeFooter(stream, values);
        stream.flush();
      } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
        throw new VaultOperationException("Invalid keys or unsupported MAC algorithm", e);
      }
    }
  }

  /**
   * Creates a stream to be used to write the vault data
   *
   * @param path the path of the vault file
   * @return the output stream
   */
  abstract S createStream(final Path path) throws FileNotFoundException;

  /**
   * Calculates the cryptographic MAC of the given collection of secure entries.
   *
   * @param values the entries to be included in the mac calculation
   * @return the cryptographic MAC
   * @throws NoSuchAlgorithmException if the chosen MAC algorithm does not exist
   * @throws InvalidKeyException      if the give used for the MAC is invalid
   */
  protected byte[] calculateMAC(final Collection<InMemoryVault.SecureEntryWrapper> values)
      throws NoSuchAlgorithmException, InvalidKeyException {
    // initialize the mac
    final Mac mac = Mac.getInstance(MAC_ALGORITHM);
    mac.init(inMemoryVault.secret);

    //TODO:
    // check performance of this lambda, 2 iterations -> map + foreach update

    // calculate the byte array length
    // 1. # entries (int)
    // 2. key len (int) + key data
    // 3. value len (int) + value data
    // 4. iv len (int) + iv data
    final int len = values.stream().mapToInt(wrapper -> {
      final byte[] key = wrapper.entry.getKey().getBytes(Vault.VAULT_CS);
      final byte[] value = wrapper.entry.getValue().getBytes(Vault.VAULT_CS);
      final byte[] iv = wrapper.iv;
      return (3 * Integer.BYTES) + key.length + value.length + iv.length;
    }).sum() + Integer.BYTES;

    // allocate the buffer
    final ByteBuffer buffer = ByteBuffer.allocate(len);

    // write the data to be maced
    buffer.putInt(values.size());
    values.forEach(wrapper -> {
      final byte[] key = wrapper.entry.getKey().getBytes(Vault.VAULT_CS);
      final byte[] value = wrapper.entry.getValue().getBytes(Vault.VAULT_CS);
      final byte[] iv = wrapper.iv;
      buffer.putInt(key.length).putInt(value.length).putInt(iv.length).put(key).put(value)
          .put(iv);
    });

    // calculate the mac
    return mac.doFinal(buffer.array());
  }

  /**
   * Calculates the MAC of the given byte data
   *
   * @param data the byte data
   * @return the mac of the byte data
   * @throws NoSuchAlgorithmException if the chosen MAC algorithm does not exist
   * @throws InvalidKeyException      if the give used for the MAC is invalid
   */
  byte[] calculateMAC(final byte[] data)
      throws NoSuchAlgorithmException, InvalidKeyException {
    // initialize the mac
    final Mac mac = Mac.getInstance(MAC_ALGORITHM);
    mac.init(inMemoryVault.secret);
    // calculate the mac
    return mac.doFinal(data);
  }

  /**
   * Writes the cryptographic MAC for the given entries to the specified stream.
   *
   * @param stream the stream where to write the data
   * @param mac    the calculated MAC
   * @throws IOException if an I/O error occurs while writing the data
   */
  abstract void writeMac(final S stream, final byte[] mac) throws IOException;

  /**
   * Writes the given entries to the specified stream.
   *
   * @param stream the stream where to write the data
   * @param values the entries to written
   * @throws IOException if an I/O error occurs while writing the data
   */
  abstract void writeEntries(final S stream,
                             final Collection<InMemoryVault.SecureEntryWrapper> values)
      throws IOException;

  /**
   * Writes the file header if applicable and/or necessary
   *
   * @param stream the stream where to write the data
   * @param values the vault entries
   * @throws IOException if an I/O error occurs while writing the data
   */
  void writeHeader(final S stream, final Collection<InMemoryVault.SecureEntryWrapper> values)
      throws IOException {
    // empty by default
  }

  /**
   * Writes the file footer if applicable and/or necessary
   *
   * @param stream the stream where to write the data
   * @param values the vault entries
   * @throws IOException if an I/O error occurs while writing the data
   */
  void writeFooter(final S stream, final Collection<InMemoryVault.SecureEntryWrapper> values)
      throws IOException {
    // empty by default
  }

  @Override
  public Collection<SecureEntry> read() {
    return inMemoryVault.read();
  }

  @Override
  public Optional<SecureEntry> read(final String key) {
    return inMemoryVault.read(key);
  }

  @Override
  public SecureEntry write(final UnsecureEntry entry) throws VaultOperationException {
    final SecureEntry secureEntry = inMemoryVault.write(entry);
    changed.set(true);
    return secureEntry;
  }

  @Override
  public Optional<SecureEntry> delete(final String key) {
    final Optional<SecureEntry> secureEntryOptional = inMemoryVault.delete(key);
    if (secureEntryOptional.isPresent()) {
      changed.set(true);
    }
    return secureEntryOptional;
  }

  @Override
  public UnsecureEntry translate(final SecureEntry entry) throws VaultOperationException {
    return inMemoryVault.translate(entry);
  }
}
