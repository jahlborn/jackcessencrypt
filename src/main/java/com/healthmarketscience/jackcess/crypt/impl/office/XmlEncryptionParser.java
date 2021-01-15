/*
Copyright (c) 2021 James Ahlborn

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.healthmarketscience.jackcess.crypt.impl.office;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import com.healthmarketscience.jackcess.crypt.InvalidCryptoConfigurationException;
import com.healthmarketscience.jackcess.crypt.model.CTDataIntegrity;
import com.healthmarketscience.jackcess.crypt.model.CTEncryption;
import com.healthmarketscience.jackcess.crypt.model.CTKeyData;
import com.healthmarketscience.jackcess.crypt.model.CTKeyEncryptor;
import com.healthmarketscience.jackcess.crypt.model.CTKeyEncryptors;
import com.healthmarketscience.jackcess.crypt.model.cert.CTCertificateKeyEncryptor;
import com.healthmarketscience.jackcess.crypt.model.cert.STCertificateKeyEncryptorUri;
import com.healthmarketscience.jackcess.crypt.model.password.CTPasswordKeyEncryptor;
import com.healthmarketscience.jackcess.crypt.model.password.STPasswordKeyEncryptorUri;
import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 *
 * @author James Ahlborn
 */
public class XmlEncryptionParser
{
  private static final String ENC_NS = "http://schemas.microsoft.com/office/2006/encryption";
  private static final String PWD_NS = "http://schemas.microsoft.com/office/2006/keyEncryptor/password";
  private static final String CERT_NS = "http://schemas.microsoft.com/office/2006/keyEncryptor/certificate";

  private static final Base64.Decoder B64_DEC = Base64.getDecoder();

  private XmlEncryptionParser() {}

  public static final CTEncryption parseEncryptionDescriptor(byte[] xmlBytes) {
    try {
      Document doc = newBuilder().parse(new ByteArrayInputStream(xmlBytes));

      Element encryptionEl = doc.getDocumentElement();
      if(!"encryption".equals(encryptionEl.getLocalName()) ||
         !ENC_NS.equals(encryptionEl.getNamespaceURI())) {
        throw new InvalidCryptoConfigurationException(
            "Unexpected xml config " + encryptionEl.getTagName());
      }

      return parseEncryption(encryptionEl);

    } catch(InvalidCryptoConfigurationException ie) {
      throw ie;
    } catch(Exception e) {
      throw new InvalidCryptoConfigurationException("Failed parsing encryption descriptor", e);
    }
  }

  private static CTEncryption parseEncryption(Element encryptionEl) {
    CTEncryption encryption = new CTEncryption();

    encryption.setKeyData(parseKeyData(getElement(encryptionEl, "keyData", ENC_NS, true)));
    encryption.setDataIntegrity(
        parseDataIntegrity(getElement(encryptionEl, "dataIntegrity", ENC_NS, false)));
    encryption.setKeyEncryptors(
        parseKeyEncryptors(getElement(encryptionEl, "keyEncryptors", ENC_NS, true)));

    return encryption;
  }

  private static CTKeyData parseKeyData(Element keyDataEl) {
    CTKeyData keyData = new CTKeyData();

    keyData.setSaltSize(getLongAttribute(keyDataEl, "saltSize"));
    keyData.setBlockSize(getLongAttribute(keyDataEl, "blockSize"));
    keyData.setKeyBits(getLongAttribute(keyDataEl, "keyBits"));
    keyData.setHashSize(getLongAttribute(keyDataEl, "hashSize"));
    keyData.setCipherAlgorithm(getStringAttribute(keyDataEl, "cipherAlgorithm"));
    keyData.setCipherChaining(getStringAttribute(keyDataEl, "cipherChaining"));
    keyData.setHashAlgorithm(getStringAttribute(keyDataEl, "hashAlgorithm"));
    keyData.setSaltValue(getBase64Attribute(keyDataEl, "saltValue"));

    return keyData;
  }

  private static CTDataIntegrity parseDataIntegrity(Element dataIntegrityEl) {
    if(dataIntegrityEl == null) {
      return null;
    }

    CTDataIntegrity dataIntegrity = new CTDataIntegrity();

    dataIntegrity.setEncryptedHmacKey(getBase64Attribute(dataIntegrityEl, "encryptedHmacKey"));
    dataIntegrity.setEncryptedHmacValue(getBase64Attribute(dataIntegrityEl, "encryptedHmacValue"));

    return dataIntegrity;
  }

  private static CTKeyEncryptors parseKeyEncryptors(Element keyEncryptorsEl) {
    CTKeyEncryptors keyEncryptors = new CTKeyEncryptors();

    for(Element encryptor : getElements(keyEncryptorsEl, "keyEncryptor", ENC_NS)) {
      keyEncryptors.getKeyEncryptor().add(parseKeyEncryptor(encryptor));
    }

    return keyEncryptors;
  }

  private static CTKeyEncryptor parseKeyEncryptor(Element keyEncryptorEl) {
    CTKeyEncryptor keyEncryptor = new CTKeyEncryptor();

    String typeUri = getStringAttribute(keyEncryptorEl, "uri");
    keyEncryptor.setUri(typeUri);

    Object encryptor = null;
    if(STPasswordKeyEncryptorUri.HTTP_SCHEMAS_MICROSOFT_COM_OFFICE_2006_KEY_ENCRYPTOR_PASSWORD.value().equals(typeUri)) {
      encryptor = parsePasswordKeyEncryptor(keyEncryptorEl);
    } else if(STCertificateKeyEncryptorUri.HTTP_SCHEMAS_MICROSOFT_COM_OFFICE_2006_KEY_ENCRYPTOR_CERTIFICATE.value().equals(typeUri)) {
      encryptor = parseCertificateKeyEncryptor(keyEncryptorEl);
    } else {
      throw createException("Unexpected xml config ", typeUri, keyEncryptorEl);
    }

    keyEncryptor.setAny(encryptor);

    return keyEncryptor;
  }

  private static CTPasswordKeyEncryptor parsePasswordKeyEncryptor(Element parentEl) {
    Element pwdEncryptorEl = getElement(parentEl, "encryptedKey", PWD_NS, true);

    CTPasswordKeyEncryptor pwdEncryptor = new CTPasswordKeyEncryptor();

    pwdEncryptor.setSaltSize(getLongAttribute(pwdEncryptorEl, "saltSize"));
    pwdEncryptor.setBlockSize(getLongAttribute(pwdEncryptorEl, "blockSize"));
    pwdEncryptor.setKeyBits(getLongAttribute(pwdEncryptorEl, "keyBits"));
    pwdEncryptor.setHashSize(getLongAttribute(pwdEncryptorEl, "hashSize"));
    pwdEncryptor.setCipherAlgorithm(getStringAttribute(pwdEncryptorEl, "cipherAlgorithm"));
    pwdEncryptor.setCipherChaining(getStringAttribute(pwdEncryptorEl, "cipherChaining"));
    pwdEncryptor.setHashAlgorithm(getStringAttribute(pwdEncryptorEl, "hashAlgorithm"));
    pwdEncryptor.setSaltValue(getBase64Attribute(pwdEncryptorEl, "saltValue"));
    pwdEncryptor.setSpinCount(getLongAttribute(pwdEncryptorEl, "spinCount"));
    pwdEncryptor.setEncryptedVerifierHashInput(getBase64Attribute(pwdEncryptorEl, "encryptedVerifierHashInput"));
    pwdEncryptor.setEncryptedVerifierHashValue(getBase64Attribute(pwdEncryptorEl, "encryptedVerifierHashValue"));
    pwdEncryptor.setEncryptedKeyValue(getBase64Attribute(pwdEncryptorEl, "encryptedKeyValue"));

    return pwdEncryptor;
  }

  private static CTCertificateKeyEncryptor parseCertificateKeyEncryptor(Element parentEl) {
    Element certEncryptorEl = getElement(parentEl, "encryptedKey", CERT_NS, true);

    CTCertificateKeyEncryptor certEncryptor = new CTCertificateKeyEncryptor();

    certEncryptor.setEncryptedKeyValue(getBase64Attribute(certEncryptorEl, "encryptedKeyValue"));
    certEncryptor.setX509Certificate(getBase64Attribute(certEncryptorEl, "x509Certificate"));
    certEncryptor.setCertVerifier(getBase64Attribute(certEncryptorEl, "certVerifier"));

    return certEncryptor;
  }

  private static Element getElement(Element parentEl, String localName, String ns,
                                    boolean required) {
    NodeList list = parentEl.getElementsByTagNameNS(ns, localName);
    if((list != null) && (list.getLength() > 0)) {
      return (Element)list.item(0);
    }
    if(!required) {
      return null;
    }
    throw createException(localName, parentEl);
  }

  private static List<Element> getElements(Element parentEl, String localName, String ns) {
    NodeList list = parentEl.getElementsByTagNameNS(ns, localName);
    if((list == null) || (list.getLength() == 0)) {
      return Collections.emptyList();
    }
    List<Element> els = new ArrayList<>();
    for(int i = 0; i < list.getLength(); ++i) {
      els.add((Element)list.item(i));
    }
    return els;
  }

  private static long getLongAttribute(Element el, String localName) {
    String attrValue = StringUtils.trimToNull(el.getAttribute(localName));
    if(attrValue == null) {
      throw createException(localName, el);
    }
    return Long.parseLong(attrValue);
  }

  private static String getStringAttribute(Element el, String localName) {
    String attrValue = StringUtils.trimToNull(el.getAttribute(localName));
    if(attrValue == null) {
      throw createException(localName, el);
    }
    return attrValue;
  }

  private static byte[] getBase64Attribute(Element el, String localName) {
    String attrValue = StringUtils.trimToNull(el.getAttribute(localName));
    if(attrValue == null) {
      throw createException(localName, el);
    }
    return B64_DEC.decode(attrValue);
  }

  private static DocumentBuilder newBuilder() throws ParserConfigurationException {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    factory.setIgnoringComments(true);
    factory.setCoalescing(true);
    factory.setNamespaceAware(true);
    return factory.newDocumentBuilder();
  }

  private static InvalidCryptoConfigurationException createException(
      String localName, Element el) {
    return createException("Could not find xml config ", localName, el);
  }

  private static InvalidCryptoConfigurationException createException(
      String context, String localName, Element el) {
    return new InvalidCryptoConfigurationException(
        context + localName + " under " + el.getTagName());
  }
}
