package pt.davidafsilva.jvault;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;

/**
 * The vaults builder.
 *
 * The builders defaults to the following settings: <table> <tr> <td><strong>Vault
 * Type</strong></td> <td>In-Memory</td> </tr> <tr> <td><strong>Iterations</strong></td> <td>{@value
 * #DEFAULT_ITERATIONS}</td> </tr> <tr> <td><strong>Key Size</strong></td> <td>{@value
 * #DEFAULT_KEY_SIZE}</td> </tr> </table>
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
              "  password: {},{}" +
              "      salt: {},{}" +
              "iterations: {},{}" +
              "  key size: {}",
              System.lineSeparator(),
              password, System.lineSeparator(),
              salt, System.lineSeparator(),
              iterations, System.lineSeparator(),
              keySize);
    final Vault vault;
    switch (type) {
      case IN_MEMORY:
        vault = new InMemoryVault(password, salt, iterations, keySize);
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
    IN_MEMORY
  }
}
