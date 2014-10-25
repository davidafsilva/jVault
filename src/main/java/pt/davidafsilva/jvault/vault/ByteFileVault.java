package pt.davidafsilva.jvault.vault;

/*
 * #%L
 * jVault
 * %%
 * Copyright (C) 2014 David Silva
 * %%
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the David Silva nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * #L%
 */

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Mac;

import pt.davidafsilva.jvault.model.SecureEntry;
import pt.davidafsilva.jvault.model.UnsecureEntry;

/**
 * A file based vault implementation, in which the data is stored in byte (raw) format.
 *
 * the format of the data is the following:
 * <pre>
 * -----------------------------------------
 * | MAC length | MAC data ....            |
 * -----------------------------------------
 * | ## Entries | Entry 1 | ... | Entry N  |
 * -----------------------------------------
 *
 * Entry format:
 * -----------------------------------------
 * | Key length | Value length | IV length |
 * -----------------------------------------
 * | Key data   | Value data   | IV data   |
 * -----------------------------------------
 * </pre>
 *
 * This implementation is backed by a {@link InMemoryVault} vault.
 *
 * @author David Silva
 */
final class ByteFileVault implements FileVault {

  // logger
  private static final Logger log = LoggerFactory.getLogger(ByteFileVault.class);

  // the MAC algorithm
  private static final String MAC_ALGORITHM = "HmacSHA256";

  // the change flag
  private final AtomicBoolean changed;

  // the backed in-memory vault
  private final InMemoryVault inMemoryVault;

  // the path/file name
  private final Path path;

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
  ByteFileVault(final String password, final String salt, final int iterations,
                final int keyLength, final Path path) throws VaultInitializationException {
    this(password.toCharArray(), salt.getBytes(StandardCharsets.UTF_8),
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
  ByteFileVault(final char[] password, final byte[] salt, final int iterations,
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
  private void buildVaultFromData(final byte[] data)
      throws VaultCorruptedException, VaultInitializationException {
    final ByteBuffer byteBuffer = ByteBuffer.wrap(data);
    // read MAC related
    ensureBufferCapacity(byteBuffer, Integer.BYTES);
    final int macLength = byteBuffer.getInt();
    if (macLength <= 0) {
      log.error("invalid MAC length read (mac len: {}b; remaining: {}b)", macLength,
                byteBuffer.remaining());
      throw new VaultCorruptedException("vault structured is corrupted");
    }
    ensureBufferCapacity(byteBuffer, macLength);
    log.debug("MAC len: {}b", macLength);

    // read mac
    final byte[] mac = new byte[macLength];
    byteBuffer.get(mac);
    if (log.isDebugEnabled()) {
      log.debug("MAC: {}", Hex.encodeHexString(mac));
    }

    // validate MAC already
    ensureBufferCapacity(byteBuffer, Integer.BYTES); // at least the # of entries must be there
    byteBuffer.mark();
    final byte[] vaultData = new byte[byteBuffer.remaining()];
    byteBuffer.get(vaultData);
    try {
      final byte[] calculatedMAC = calculateMAC(vaultData);
      if (!Arrays.equals(mac, calculatedMAC)) {
        log.error("invalid MAC found: {}", Hex.encodeHexString(calculatedMAC));
        throw new VaultCorruptedException("vault structured is corrupted");
      }
    } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
      log.error("invalid keys / mac algorithm", e);
      throw new VaultInitializationException("Invalid keys or unsupported MAC algorithm", e);
    }

    byteBuffer.reset();
    // read vault data
    final int totalEntries = byteBuffer.getInt();
    log.debug("found {} secure entries", totalEntries);
    for (int idx = 0; idx < totalEntries; idx++) {
      // ensure that 3 integers are stored
      ensureBufferCapacity(byteBuffer, 3 * Integer.BYTES);

      // read entry data lengths
      final byte[] key = new byte[byteBuffer.getInt()];
      final byte[] value = new byte[byteBuffer.getInt()];
      final byte[] iv = new byte[byteBuffer.getInt()];

      // ensure that all the data is stored
      ensureBufferCapacity(byteBuffer, key.length + value.length + iv.length);

      // read the data
      byteBuffer.get(key);
      byteBuffer.get(value);
      byteBuffer.get(iv);

      // create the entry
      final SecureEntry secureEntry = SecureEntry.of(new String(key, StandardCharsets.UTF_8),
                                                     new String(value, StandardCharsets.UTF_8));
      final InMemoryVault.SecureEntryWrapper secureEntryWrapper =
          new InMemoryVault.SecureEntryWrapper(secureEntry, iv);
      // write entry to the vault
      inMemoryVault.store(secureEntry, secureEntryWrapper);
    }

    // the buffer must be empty here!
    ensureBufferCapacity(byteBuffer, 0);
  }

  /**
   * Ensures that the specified buffer has enough {@code bytes} left to be read
   *
   * @param buffer the byte buffer with the vault data
   * @param bytes  the number of bytes
   * @throws VaultCorruptedException if the buffer has not the given bytes available to be read
   */
  private void ensureBufferCapacity(final ByteBuffer buffer, final int bytes) {
    if (bytes > buffer.remaining()) {
      throw new VaultCorruptedException("vault structured is corrupted");
    }
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
      try (final DataOutputStream stream = new DataOutputStream(
          new FileOutputStream(path.toFile()))) {
        writeMac(stream, values);
        writeEntries(stream, values);
        stream.flush();
      } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
        throw new VaultOperationException("Invalid keys or unsupported MAC algorithm", e);
      }
    }
  }

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
      final byte[] key = wrapper.entry.getKey().getBytes(StandardCharsets.UTF_8);
      final byte[] value = wrapper.entry.getValue().getBytes(StandardCharsets.UTF_8);
      final byte[] iv = wrapper.iv;
      return (3 * Integer.BYTES) + key.length + value.length + iv.length;
    }).sum() + Integer.BYTES;

    // allocate the buffer
    final ByteBuffer buffer = ByteBuffer.allocate(len);

    // write the data to be maced
    buffer.putInt(values.size());
    values.forEach(wrapper -> {
      final byte[] key = wrapper.entry.getKey().getBytes(StandardCharsets.UTF_8);
      final byte[] value = wrapper.entry.getValue().getBytes(StandardCharsets.UTF_8);
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
  protected byte[] calculateMAC(final byte[] data)
      throws NoSuchAlgorithmException, InvalidKeyException {
    // initialize the mac
    final Mac mac = Mac.getInstance(MAC_ALGORITHM);
    mac.init(inMemoryVault.secret);
    // calculate the mac
    return mac.doFinal(data);
  }

  /**
   * Calculates and writes the cryptographic MAC for the given entries to the specified stream.
   *
   * @param stream the stream where to write the data
   * @param values the entries to be included in the mac calculation
   * @throws IOException              if an I/O error occurs while writing the data
   * @throws NoSuchAlgorithmException if the chosen MAC algorithm does not exist
   * @throws InvalidKeyException      if the give used for the MAC is invalid
   */

  private void writeMac(final DataOutputStream stream,
                        final Collection<InMemoryVault.SecureEntryWrapper> values)
      throws IOException, InvalidKeyException, NoSuchAlgorithmException {
    // calculate and write the MAC
    final byte[] mac = calculateMAC(values);
    stream.writeInt(mac.length);
    stream.write(mac);
    if (log.isDebugEnabled()) {
      log.debug("writing MAC: {}", Hex.encodeHexString(mac));
    }
  }

  /**
   * Calculates and writes the given entries to the specified stream.
   *
   * @param stream the stream where to write the data
   * @param values the entries to written
   * @throws IOException if an I/O error occurs while writing the data
   */
  private void writeEntries(final DataOutputStream stream,
                            final Collection<InMemoryVault.SecureEntryWrapper> values)
      throws IOException {
    // write the # of entries
    stream.writeInt(values.size());
    // store the vault values
    values.forEach(wrapper -> {
      final byte[] key = wrapper.entry.getKey().getBytes(StandardCharsets.UTF_8);
      final byte[] value = wrapper.entry.getValue().getBytes(StandardCharsets.UTF_8);
      final byte[] iv = wrapper.iv;
      try {
        stream.writeInt(key.length);
        stream.writeInt(value.length);
        stream.writeInt(iv.length);
        stream.write(key);
        stream.write(value);
        stream.write(iv);
        if (log.isDebugEnabled()) {
          log.debug("writing entry: {}", wrapper);
        }
      } catch (final IOException ioe) {
        throw new UncheckedIOException(ioe);
      }
    });
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
