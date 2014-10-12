package pt.davidafsilva.jvault;

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

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import static java.util.stream.Collectors.toList;

/**
 * An im-memory secure vault implementation
 *
 * @author David Silva
 */
public final class InMemoryVault implements Vault {

  // vault cipher settings
  private static final String CIPHER_SETTINGS = "AES/CBC/PKCS5Padding";

  // vault secret settings
  private static final String SECRET_SETTINGS = "PBKDF2WithHmacSHA1";

  // vault secret algorithm
  private static final String SECRET_ALGORITHM = "AES";

  // the map where key-value entries are stored
  private final Map<String, SecureEntryWrapper> map = new ConcurrentHashMap<>();

  // properties
  private final SecretKey secret;

  /**
   * Creates a vault with the specified parameters.
   *
   * @param password   the vaults password for PBE
   * @param salt       the salt (should be a random) to protect against dictionary attacks
   * @param iterations the number of iterations to be applied when deriving the actual cipher key
   * @param keyLength  the size of the key to be used for encryption (affects the salt size asl
   *                   well)
   * @throws VaultInitializationException if an error occurs while initializing the vault
   */
  InMemoryVault(final String password, final String salt, final int iterations,
                final int keyLength) throws VaultInitializationException {
    this(password.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), iterations, keyLength);
  }

  /**
   * Creates a vault with the specified parameters.
   *
   * @param password   the vaults password for PBE
   * @param salt       the salt (should be a random) to protect against dictionary attacks
   * @param iterations the number of iterations to be applied when deriving the actual cipher key
   * @param keyLength  the size of the key to be used for encryption (affects the salt size asl
   *                   well)
   * @throws VaultInitializationException if an error occurs while initializing the vault
   */
  InMemoryVault(final char[] password, final byte[] salt, final int iterations,
                final int keyLength) throws VaultInitializationException {
    try {
      // create the secret factory with the configure settings
      final SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_SETTINGS);

      // create the key from the password and salt
      final KeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);

      // create the secret from the derived key using AES
      secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), SECRET_ALGORITHM);
    } catch (final InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new VaultInitializationException("An error occurred while initializing the vault.", e);
    }
  }

  @Override
  public Collection<SecureEntry> read() {
    return Collections.unmodifiableCollection(
        map.values().stream().map(wrapper -> wrapper.entry).collect(toList()));
  }

  @Override
  public Optional<SecureEntry> read(final String key) {
    final SecureEntryWrapper secureEntryWrapper = map.get(key);
    return Optional.ofNullable(secureEntryWrapper == null ? null : secureEntryWrapper.entry);
  }

  @Override
  public SecureEntry write(final UnsecureEntry entry) throws VaultOperationException {
    final SecureEntryWrapper secureEntryWrapper = secure(entry);
    map.put(entry.getKey(), secureEntryWrapper);
    return secureEntryWrapper.entry;
  }

  @Override
  public Optional<SecureEntry> delete(final String key) {
    final SecureEntryWrapper secureEntryWrapper = map.remove(key);
    return Optional.ofNullable(secureEntryWrapper == null ? null : secureEntryWrapper.entry);
  }

  @Override
  public UnsecureEntry translate(final SecureEntry entry) throws VaultOperationException {
    final SecureEntryWrapper secureEntryWrapper = map.get(entry.getKey());
    if (secureEntryWrapper == null) {
      throw new IllegalArgumentException(
          String.format("no such key '%s' in the vault.", entry.getKey()));
    }
    return unsecure(secureEntryWrapper);
  }

  /**
   * Secures the specified entry
   *
   * @param entry the entry to be secured
   * @return the secured entry
   * @throws VaultOperationException if an error occurs while ciphering the entry
   */
  private SecureEntryWrapper secure(final UnsecureEntry entry) throws VaultOperationException {
    try {
      // get the byte data
      final byte[] bValue = entry.getValue().getBytes(StandardCharsets.UTF_8);

      // get the cipher algorithm instance
      final Cipher cipher = Cipher.getInstance(CIPHER_SETTINGS);

      // initialize the cipher for encryption with the secret
      cipher.init(Cipher.ENCRYPT_MODE, secret);

      // cipher the entry value
      final byte[] cValue = cipher.doFinal(bValue);

      // extract the generated initial vector parameter
      final byte[] initVector = cipher.getParameters().getParameterSpec(IvParameterSpec.class)
          .getIV();

      // create the secure entry
      final SecureEntry secureEntry = SecureEntry.of(entry.getKey(), Hex.encodeHexString(cValue));

      // create the wrapper with the IV
      final SecureEntryWrapper entryWrapper = new SecureEntryWrapper(secureEntry, initVector);

      // store it in the map
      map.put(entry.getKey(), entryWrapper);

      return entryWrapper;
    } catch (final NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeyException |
        BadPaddingException | InvalidParameterSpecException | NoSuchPaddingException e) {
      throw new VaultOperationException(
          String.format("An error occurred while ciphering the entry with key: %s", entry.getKey()),
          e);
    }
  }

  /**
   * Unsecures the specified entry
   *
   * @param entry the entry to be unsecured
   * @return the unsecured entry
   * @throws VaultOperationException if an error occurs while ciphering the entry
   */
  private UnsecureEntry unsecure(final SecureEntryWrapper entry) throws VaultOperationException {
    try {
      // get the byte data
      final byte[] bValue = Hex.decodeHex(entry.entry.getValue().toCharArray());
      // get the cipher algorithm instance
      final Cipher cipher = Cipher.getInstance(CIPHER_SETTINGS);
      // initialize the cipher for decryption with both secret and initial vector
      cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(entry.iv));
      // decipher and convert
      return UnsecureEntry.of(entry.entry.getKey(),
                              new String(cipher.doFinal(bValue), StandardCharsets.UTF_8));
    } catch (final NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException |
        IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException |
        DecoderException e) {
      throw new VaultOperationException(
          String.format("An error occurred while deciphering the entry with key: %s",
                        entry.entry.getKey()), e);
    }
  }


  /**
   * The wrapper class for a secure entry, which adds the necessary initial vector used in the
   * cipher of the {@link pt.davidafsilva.jvault.Entry}.
   */
  static class SecureEntryWrapper {

    // properties
    final SecureEntry entry;
    final byte[] iv;

    /**
     * Default wrapper constructor
     *
     * @param entry the original secure entry
     * @param iv    the IV used in the cipher
     */
    private SecureEntryWrapper(final SecureEntry entry, final byte[] iv) {
      this.entry = entry;
      this.iv = iv;
    }
  }
}
