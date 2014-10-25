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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;

/**
 * The vaults builder.
 *
 * The builders defaults to the following settings:
 * <table>
 *   <tr>
 *     <td><strong>Vault Type</strong></td>
 *     <td>In-Memory</td>
 *   </tr>
 *   <tr>
 *     <td><strong>Iterations</strong></td>
 *     <td>{@value #DEFAULT_ITERATIONS}</td>
 *   </tr>
 *   <tr>
 *     <td><strong>Key Size</strong></td>
 *     <td>{@value #DEFAULT_KEY_SIZE}</td>
 *   </tr>
 * </table>
 *
 * @author David Silva
 */
public final class VaultBuilder {

  // logger
  private static final Logger log = LoggerFactory.getLogger(VaultBuilder.class);

  // static properties / defaults
  private static final Collection<Integer> SUPPORTED_KEY_SIZES = Arrays.asList(128, 192, 256);
  private static final int DEFAULT_ITERATIONS = 65536;
  private static final int DEFAULT_KEY_SIZE = 256;
  private static final VaultType DEFAULT_VAULT_TYPE = VaultType.IN_MEMORY;

  // properties
  private VaultType type = DEFAULT_VAULT_TYPE;
  private char[] password;
  private byte[] salt;
  private int iterations = DEFAULT_ITERATIONS;
  private int keySize = DEFAULT_KEY_SIZE;
  private Path path;

  // private constructor
  private VaultBuilder() {
  }

  /**
   * Creates a new instance of this builder
   *
   * @return the builder's instance
   */
  public static VaultBuilder create() {
    return new VaultBuilder();
  }

  /**
   * Selects the in-memory vault implementation to be built.
   *
   * @return the current builder
   */
  public VaultBuilder inMemory() {
    this.type = VaultType.IN_MEMORY;
    return this;
  }

  /**
   * Selects the raw file vault implementation to be built.
   *
   * @param path the vault file
   * @return the current builder
   */
  public VaultBuilder rawFile(final Path path) {
    Objects.requireNonNull(path, "Invalid vault file");
    final File fp = path.toFile();
    if (fp.exists() && (!fp.isFile() || !fp.canRead())) {
      throw new IllegalArgumentException("Invalid vault file, not a file or no read permissions");
    } else if (!fp.canWrite()) {
      throw new IllegalArgumentException("Invalid vault file, no write permissions");
    }
    this.path = path;
    this.type = VaultType.RAW_FILE;
    return this;
  }

  /**
   * Defines the password to be used by the vault
   *
   * @param password the vault's password
   * @return the current builder
   */
  public VaultBuilder password(final String password) {
    Objects.requireNonNull(password, "Invalid password");
    this.password = password.toCharArray();
    return this;
  }

  /**
   * Defines the password to be used by the vault
   *
   * @param password the vault's password
   * @return the current builder
   */
  public VaultBuilder password(final char[] password) {
    Objects.requireNonNull(password, "Invalid password");
    this.password = Arrays.copyOf(password, password.length);
    return this;
  }

  /**
   * Defines the salt to be used by the vault
   *
   * @param salt the vault's salt
   * @return the current builder
   */
  public VaultBuilder salt(final String salt) {
    Objects.requireNonNull(salt, "Invalid salt");
    this.salt = salt.getBytes(StandardCharsets.UTF_8);
    return this;
  }

  /**
   * Defines the salt to be used by the vault
   *
   * @param salt the vault's salt
   * @return the current builder
   */
  public VaultBuilder salt(final byte[] salt) {
    Objects.requireNonNull(salt, "Invalid salt");
    this.salt = Arrays.copyOf(salt, salt.length);
    return this;
  }

  /**
   * Defines the number of iterations (rounds) to be executed when deriving the key
   *
   * @param iterations the number of key iterations
   * @return the current builder
   */
  public VaultBuilder iterations(final int iterations) {
    if (iterations < 0) {
      throw new IllegalArgumentException("invalid number of iterations, must be greater than 0");
    }
    this.iterations = iterations;
    return this;
  }

  /**
   * Defines the length of the key to be used by the ciphering algorithm.
   *
   * Since AES is being used, only 3 key sizes are supported: 128, 192, 256.
   *
   * @param keySize the key size
   * @return the current builder
   */
  public VaultBuilder keySize(final int keySize) {
    if (!SUPPORTED_KEY_SIZES.contains(keySize)) {
      throw new IllegalArgumentException("Unsupported key length provided");
    }
    this.keySize = keySize;
    return this;
  }

  /**
   * Builds the vault based on the current builder state.
   *
   * @return the vault implementation
   * @throws VaultInitializationException if an error occurs while initializing the vault.
   */
  public Vault build() throws VaultInitializationException {
    Objects.requireNonNull(password, "A valid password must be set");
    Objects.requireNonNull(salt, "A valid salt must be set");
    // debug should not be enabled in production!
    log.debug("Creating a vault with the settings:{}" +
              "      type: {},{}" +
              "  password: {},{}" +
              "      salt: {},{}" +
              "iterations: {},{}" +
              "  key size: {},{}" +
              "      path: {}",
              System.lineSeparator(),
              password, System.lineSeparator(),
              type, System.lineSeparator(),
              salt, System.lineSeparator(),
              iterations, System.lineSeparator(),
              keySize, System.lineSeparator(),
              path);
    final Vault vault;
    switch (type) {
      case IN_MEMORY:
        vault = new InMemoryVault(password, salt, iterations, keySize);
        break;
      case RAW_FILE:
        vault = new ByteFileVault(password, salt, iterations, keySize, path);
        break;
      default:
        throw new IllegalStateException();
    }

    return vault;
  }

  /**
   * The enumeration of currently supported vault types
   */
  private enum VaultType {
    IN_MEMORY,
    RAW_FILE
  }
}
