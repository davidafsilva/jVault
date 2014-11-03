package pt.davidafsilva.jvault.vault;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.CharArrayReader;
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

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.XMLEvent;

import pt.davidafsilva.jvault.model.SecureEntry;

import static org.apache.commons.lang3.StringEscapeUtils.escapeXml11;
import static org.apache.commons.lang3.StringEscapeUtils.unescapeXml;

/**
 * A XML file based vault implementation.
 *
 * the format of the data is the following:
 * <pre>
 * {@code
 *   <?xml version="1.1" encoding="UTF-8" standalone="yes"?>
 *   <vault>
 *     <mac></mac>
 *     <entries>
 *       <entry>
 *         <key>key</key>
 *         <value>hex encoded value</value>
 *         <iv>hex encoded IV</iv>
 *       </entry>
 *       <entry>
 *         ...
 *       </entry>
 *     </entries>
 *   </vault>
 * }
 * </pre>
 *
 * This implementation is backed by a {@link InMemoryVault} vault.
 *
 * @author David Silva
 */
public class XmlFileVault extends AbstractFileVault<DataOutputStream> {

  // logger
  private static final Logger log = LoggerFactory.getLogger(XmlFileVault.class);

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
  XmlFileVault(final String password, final String salt, final int iterations,
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
  XmlFileVault(final char[] password, final byte[] salt, final int iterations,
               final int keyLength, final Path path) throws VaultInitializationException {
    super(password, salt, iterations, keyLength, path);
  }

  @Override
  void buildVaultFromData(final byte[] data) throws VaultCorruptedException,
                                                    VaultInitializationException {
    XMLStreamReader reader = null;
    try {
      // load the XML
      final char[] decodedData = VAULT_CS.decode(ByteBuffer.wrap(data)).array();
      reader = XMLInputFactory.newInstance().createXMLStreamReader(
          new CharArrayReader(decodedData));

      // parse the vault data

      // 0. <?xml?> header
      if (!reader.hasNext() || reader.getEventType() != XMLEvent.START_DOCUMENT) {
        log.error("unable to read vault document start");
        vaultCorrupted();
      }

      // 1. <vault>
      if (!reader.hasNext() || reader.next() != XMLEvent.START_ELEMENT || !"vault"
          .equals(reader.getLocalName())) {
        log.error("unable to read vault root (start) element");
        vaultCorrupted();
      }

      // 2 <mac>
      if (!reader.hasNext() || reader.next() != XMLEvent.START_ELEMENT || !"mac"
          .equals(reader.getLocalName())) {
        log.error("unable to read vault mac element");
        vaultCorrupted();
      }
      final byte[] mac = Hex.decodeHex(reader.getElementText().toCharArray());
      if (log.isDebugEnabled()) {
        log.debug("MAC: {}", Hex.encodeHexString(mac));
      }

      // 3 <numberEntries>
      if (!reader.hasNext() || reader.next() != XMLEvent.START_ELEMENT || !"numberEntries"
          .equals(reader.getLocalName())) {
        log.error("unable to read vault mac element");
        vaultCorrupted();
      }
      final int numberEntries = Integer.valueOf(reader.getElementText());
      if (numberEntries < 0) {
        log.error("invalid number of entries read from the vault: {}", numberEntries);
        vaultCorrupted();
      }

      // 4. <entries>
      if (!reader.hasNext() || reader.next() != XMLEvent.START_ELEMENT || !"entries"
          .equals(reader.getLocalName())) {
        log.error("unable to read vault entries (start) element");
        vaultCorrupted();
      }

      // 5. <entry>?</entry> ...
      for (int i = 0; i < numberEntries; i++) {
        if (!reader.hasNext() || reader.next() != XMLEvent.START_ELEMENT || !"entry"
            .equals(reader.getLocalName())) {
          log.error("unable to read vault entry (start) element");
          vaultCorrupted();
        }

        // 5.1 <key>
        if (!reader.hasNext() || reader.next() != XMLEvent.START_ELEMENT || !"key"
            .equals(reader.getLocalName())) {
          log.error("unable to read vault entry key element");
          vaultCorrupted();
        }
        final String key = unescapeXml(reader.getElementText());

        // 5.2 <value>
        if (!reader.hasNext() || reader.next() != XMLEvent.START_ELEMENT || !"value"
            .equals(reader.getLocalName())) {
          log.error("unable to read vault entry value element");
          vaultCorrupted();
        }
        final String value = reader.getElementText();

        // 5.3 <iv>
        if (!reader.hasNext() || reader.next() != XMLEvent.START_ELEMENT || !"iv"
            .equals(reader.getLocalName())) {
          log.error("unable to read vault entry IV element");
          vaultCorrupted();
        }
        final byte[] iv = Hex.decodeHex(reader.getElementText().toCharArray());

        // 5.4  </entry>
        if (!reader.hasNext() || reader.next() != XMLEvent.END_ELEMENT || !"entry"
            .equals(reader.getLocalName())) {
          log.error("unable to read vault entry (end) element");
          vaultCorrupted();
        }

        // create the entry
        final SecureEntry secureEntry = SecureEntry.of(key, value);
        final InMemoryVault.SecureEntryWrapper secureEntryWrapper =
            new InMemoryVault.SecureEntryWrapper(secureEntry, iv);
        // write entry to the vault
        inMemoryVault.store(secureEntry, secureEntryWrapper);
      }

      // 6. </entries>
      if (!reader.hasNext() || reader.next() != XMLEvent.END_ELEMENT || !"entries"
          .equals(reader.getLocalName())) {
        log.error("unable to read vault entries (end) element");
        vaultCorrupted();
      }

      // 7. </vault>
      if (!reader.hasNext() || reader.next() != XMLEvent.END_ELEMENT || !"vault"
          .equals(reader.getLocalName())) {
        log.error("unable to read vault root (end) element");
        vaultCorrupted();
      }

      // end of document
      if (!reader.hasNext() || reader.next() != XMLEvent.END_DOCUMENT || reader.hasNext()) {
        log.error("unable to read vault document end");
        vaultCorrupted();
      }

      // 8. check mac
      final byte[] calculatedMAC = calculateMAC(inMemoryVault.map.values());
      if (!Arrays.equals(mac, calculatedMAC)) {
        log.error("invalid MAC found: {}", Hex.encodeHexString(calculatedMAC));
        vaultCorrupted();
      }
    } catch (final XMLStreamException | DecoderException | NumberFormatException e) {
      log.error("Unable to load XML vault", e);
      throw new VaultCorruptedException("Invalid XML vault file");
    } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
      log.error("invalid keys / mac algorithm", e);
      throw new VaultInitializationException("Invalid keys or unsupported MAC algorithm", e);
    } finally {
      if (reader != null) {
        try {
          reader.close();
        } catch (final XMLStreamException e) {
          log.error("error closing XML vault file", e);
        }
      }
    }
  }

  @Override
  DataOutputStream createStream(final Path path) throws FileNotFoundException {
    return new DataOutputStream(new FileOutputStream(path.toFile()));
  }

  @Override
  void writeHeader(final DataOutputStream stream,
                   final Collection<InMemoryVault.SecureEntryWrapper> values) throws IOException {
    stream.writeBytes("<?xml version=\"1.1\" encoding=\"UTF-8\" standalone=\"yes\"?>");
    stream.writeBytes("<vault>");
  }

  @Override
  void writeFooter(final DataOutputStream stream,
                   final Collection<InMemoryVault.SecureEntryWrapper> values) throws IOException {
    stream.writeBytes("</vault>");
  }

  @Override
  void writeMac(final DataOutputStream stream, final byte[] mac) throws IOException {
    if (log.isDebugEnabled()) {
      log.debug("writing MAC: {}", Hex.encodeHexString(mac));
    }
    stream.writeBytes("<mac>" + Hex.encodeHexString(mac) + "</mac>");
  }

  @Override
  void writeEntries(final DataOutputStream stream,
                    final Collection<InMemoryVault.SecureEntryWrapper> values) throws IOException {
    // store the vault values
    stream.writeBytes("<numberEntries>" + values.size() + "</numberEntries>");
    stream.writeBytes("<entries>");
    values.forEach(wrapper -> {
      final String key = wrapper.entry.getKey();
      final String value = wrapper.entry.getValue();
      final String iv = Hex.encodeHexString(wrapper.iv);
      try {
        if (log.isDebugEnabled()) {
          log.debug("writing entry: {}", wrapper);
        }
        stream.writeBytes("<entry>");
        stream.writeBytes("<key>" + escapeXml11(key) + "</key>");
        stream.writeBytes("<value>" + value + "</value>");
        stream.writeBytes("<iv>" + iv + "</iv>");
        stream.writeBytes("</entry>");
      } catch (final IOException ioe) {
        log.error("error while writing the entry", ioe);
        throw new UncheckedIOException(ioe);
      }
    });
    stream.writeBytes("</entries>");
  }
}
