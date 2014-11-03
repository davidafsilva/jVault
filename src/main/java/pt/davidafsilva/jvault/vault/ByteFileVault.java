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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

import pt.davidafsilva.jvault.model.SecureEntry;

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
final class ByteFileVault extends AbstractFileVault<DataOutputStream> {

  // logger
  private static final Logger log = LoggerFactory.getLogger(ByteFileVault.class);

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
    super(password, salt, iterations, keyLength, path);
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
    super(password, salt, iterations, keyLength, path);
  }

  @Override
  DataOutputStream createStream(final Path path) throws FileNotFoundException {
    return new DataOutputStream(new FileOutputStream(path.toFile()));
  }

  /**
   * Builds the vault from the given data, previously read from the file
   *
   * @param data the file data
   * @throws VaultCorruptedException if the data is corrupted
   */
  @Override
  void buildVaultFromData(final byte[] data)
      throws VaultCorruptedException, VaultInitializationException {
    final ByteBuffer byteBuffer = ByteBuffer.wrap(data);
    // read MAC related
    ensureBufferCapacity(byteBuffer, Integer.BYTES);
    final int macLength = byteBuffer.getInt();
    if (macLength <= 0) {
      log.error("invalid MAC length read (mac len: {}b; remaining: {}b)", macLength,
                byteBuffer.remaining());
      vaultCorrupted();
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
        vaultCorrupted();
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
      final SecureEntry secureEntry = SecureEntry.of(new String(key, Vault.VAULT_CS),
                                                     new String(value, Vault.VAULT_CS));
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

  @Override
  void writeMac(final DataOutputStream stream, final byte[] mac) throws IOException {
    if (log.isDebugEnabled()) {
      log.debug("writing MAC: {}", Hex.encodeHexString(mac));
    }
    stream.writeInt(mac.length);
    stream.write(mac);
  }

  @Override
  void writeEntries(final DataOutputStream stream,
                    final Collection<InMemoryVault.SecureEntryWrapper> values) throws IOException {
    // write the # of entries
    stream.writeInt(values.size());
    // store the vault values
    values.forEach(wrapper -> {
      final byte[] key = wrapper.entry.getKey().getBytes(Vault.VAULT_CS);
      final byte[] value = wrapper.entry.getValue().getBytes(Vault.VAULT_CS);
      final byte[] iv = wrapper.iv;
      try {
        if (log.isDebugEnabled()) {
          log.debug("writing entry: {}", wrapper);
        }
        stream.writeInt(key.length);
        stream.writeInt(value.length);
        stream.writeInt(iv.length);
        stream.write(key);
        stream.write(value);
        stream.write(iv);
      } catch (final IOException ioe) {
        throw new UncheckedIOException(ioe);
      }
    });
  }
}
