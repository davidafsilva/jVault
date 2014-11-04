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

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.io.SerializedString;

import org.apache.commons.codec.DecoderException;
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

import static org.apache.commons.lang3.StringEscapeUtils.escapeJson;
import static org.apache.commons.lang3.StringEscapeUtils.unescapeJson;

/**
 * A JSON file based vault implementation.
 *
 * the format of the data is the following:
 * <pre>
 * {@code
 *  {
 *    "vault": {
 *      "mac": "...",
 *      "numberEntries": #,
 *      "entries": [
 *        {"key": "key", "value": "hex encoded value", "iv": "hex encoded IV"},
 *        ...
 *      ]
 *    }
 *  }
 * </pre>
 *
 * This implementation is backed by a {@link InMemoryVault} vault.
 *
 * @author David Silva
 */
final class JsonFileVault extends AbstractFileVault<DataOutputStream> {

  // logger
  private static final Logger log = LoggerFactory.getLogger(JsonFileVault.class);

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
  JsonFileVault(final String password, final String salt, final int iterations,
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
  JsonFileVault(final char[] password, final byte[] salt, final int iterations,
                final int keyLength, final Path path) throws VaultInitializationException {
    super(password, salt, iterations, keyLength, path);
  }


  @Override
  void buildVaultFromData(final byte[] data)
      throws VaultCorruptedException, VaultInitializationException {
    // create the JSON parser
    try (final JsonParser parser = new JsonFactory().createParser(VAULT_CS.decode(
        ByteBuffer.wrap(data)).array())) {

      // 0. JSON start object
      if (parser.nextToken() != JsonToken.START_OBJECT) {
        log.error("unable to read vault object start");
        vaultCorrupted();
      }

      // 1. "vault": {
      if (!parser.nextFieldName(new SerializedString("vault"))
          || parser.nextToken() != JsonToken.START_OBJECT) {
        log.error("unable to read vault root (start) field");
        vaultCorrupted();
      }

      // 2. "mac"
      if (!parser.nextFieldName(new SerializedString("mac"))
          || parser.nextToken() != JsonToken.VALUE_STRING) {
        log.error("unable to read vault mac field");
        vaultCorrupted();
      }
      final byte[] mac = Hex.decodeHex(parser.getText().toCharArray());
      if (log.isDebugEnabled()) {
        log.debug("MAC: {}", Hex.encodeHexString(mac));
      }

      // 3. "numberEntries"
      if (!parser.nextFieldName(new SerializedString("numberEntries"))
          || parser.nextToken() != JsonToken.VALUE_NUMBER_INT) {
        log.error("unable to read vault numberEntries field");
        vaultCorrupted();
      }
      final int numberEntries = parser.getIntValue();
      if (numberEntries < 0) {
        log.error("invalid number of entries read from the vault: {}", numberEntries);
        vaultCorrupted();
      }

      // 4. "entries": [
      if (!parser.nextFieldName(new SerializedString("entries"))
          || parser.nextToken() != JsonToken.START_ARRAY) {
        log.error("unable to read vault entries (start) field");
        vaultCorrupted();
      }

      // 5. {?} (entry) ...
      for (int i = 0; i < numberEntries; i++) {
        // 5.0 start object: {
        if (parser.nextToken() != JsonToken.START_OBJECT) {
          log.error("unable to read entry object start");
          vaultCorrupted();
        }

        // 5.1 "key"
        if (!parser.nextFieldName(new SerializedString("key"))
            || parser.nextToken() != JsonToken.VALUE_STRING) {
          log.error("unable to read vault entry key field");
          vaultCorrupted();
        }
        final String key = unescapeJson(parser.getText());

        // 5.2 "value"
        if (!parser.nextFieldName(new SerializedString("value"))
            || parser.nextToken() != JsonToken.VALUE_STRING) {
          log.error("unable to read vault entry value field");
          vaultCorrupted();
        }
        final String value = parser.getText();

        // 5.3 "iv"
        if (!parser.nextFieldName(new SerializedString("iv"))
            || parser.nextToken() != JsonToken.VALUE_STRING) {
          log.error("unable to read vault entry IV field");
          vaultCorrupted();
        }
        final byte[] iv = Hex.decodeHex(parser.getText().toCharArray());

        // 5.4 close object: }
        if (parser.nextToken() != JsonToken.END_OBJECT) {
          log.error("unable to read vault entry (end) field");
          vaultCorrupted();
        }

        // create the entry
        final SecureEntry secureEntry = SecureEntry.of(key, value);
        final InMemoryVault.SecureEntryWrapper secureEntryWrapper =
            new InMemoryVault.SecureEntryWrapper(secureEntry, iv);
        // write entry to the vault
        inMemoryVault.store(secureEntry, secureEntryWrapper);
      }

      // 6. ] end array
      if (parser.nextToken() != JsonToken.END_ARRAY) {
        log.error("unable to read vault entries (end) field");
        vaultCorrupted();
      }

      // 7. end vault: }
      if (parser.nextToken() != JsonToken.END_OBJECT) {
        log.error("unable to read vault root (end) field");
        vaultCorrupted();
      }

      // end of object
      if (parser.nextToken() != JsonToken.END_OBJECT || parser.nextToken() != null) {
        log.error("unable to read vault object end");
        vaultCorrupted();
      }

      // 8. check mac
      final byte[] calculatedMAC = calculateMAC(inMemoryVault.map.values());
      if (!Arrays.equals(mac, calculatedMAC)) {
        log.error("invalid MAC found: {}", Hex.encodeHexString(calculatedMAC));
        vaultCorrupted();
      }
    } catch (final IOException | DecoderException e) {
      log.error("Unable to load JSON vault", e);
      vaultCorrupted();
    } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
      log.error("invalid keys / mac algorithm", e);
      throw new VaultInitializationException("Invalid keys or unsupported MAC algorithm", e);
    }
  }

  @Override
  DataOutputStream createStream(final Path path) throws FileNotFoundException {
    return new DataOutputStream(new FileOutputStream(path.toFile()));
  }

  @Override
  void writeHeader(final DataOutputStream stream,
                   final Collection<InMemoryVault.SecureEntryWrapper> values) throws IOException {
    stream.writeBytes("{\"vault\":{");
  }

  @Override
  void writeFooter(final DataOutputStream stream,
                   final Collection<InMemoryVault.SecureEntryWrapper> values) throws IOException {
    stream.writeBytes("}}");
  }

  @Override
  void writeMac(final DataOutputStream stream, final byte[] mac) throws IOException {
    if (log.isDebugEnabled()) {
      log.debug("writing MAC: {}", Hex.encodeHexString(mac));
    }
    stream.writeBytes("\"mac\":\"" + Hex.encodeHexString(mac) + "\",");
  }

  @Override
  void writeEntries(final DataOutputStream stream,
                    final Collection<InMemoryVault.SecureEntryWrapper> values) throws IOException {
    // store the vault values
    stream.writeBytes("\"numberEntries\":" + values.size() + ",");
    stream.writeBytes("\"entries\":[");
    final int[] missing = {values.size()};
    values.forEach(wrapper -> {
      final String key = wrapper.entry.getKey();
      final String value = wrapper.entry.getValue();
      final String iv = Hex.encodeHexString(wrapper.iv);
      try {
        if (log.isDebugEnabled()) {
          log.debug("writing entry: {}", wrapper);
        }
        stream.writeBytes("{\"key\":\"" + escapeJson(key) + "\",");
        stream.writeBytes("\"value\":\"" + value + "\",");
        stream.writeBytes("\"iv\":\"" + iv + "\"}");
        if (--missing[0] > 0) {
          stream.writeBytes(",");
        }
      } catch (final IOException ioe) {
        log.error("error while writing the entry", ioe);
        throw new UncheckedIOException(ioe);
      }
    });
    stream.writeBytes("]");
  }

}
