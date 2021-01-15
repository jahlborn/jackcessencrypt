//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-661
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a>
// Any modifications to this file will be lost upon recompilation of the source schema.
// Generated on: 2021.01.15 at 11:43:19 AM EST
//


package com.healthmarketscience.jackcess.crypt.model;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Java class for CT_KeyEncryptors complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="CT_KeyEncryptors">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="keyEncryptor" type="{http://schemas.microsoft.com/office/2006/encryption}CT_KeyEncryptor" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 *
 *
 */
// @XmlAccessorType(XmlAccessType.FIELD)
// @XmlType(name = "CT_KeyEncryptors", propOrder = {
//     "keyEncryptor"
// })
public class CTKeyEncryptors {

    // @XmlElement(required = true)
    protected List<CTKeyEncryptor> keyEncryptor;

    /**
     * Gets the value of the keyEncryptor property.
     *
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the keyEncryptor property.
     *
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getKeyEncryptor().add(newItem);
     * </pre>
     *
     *
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link CTKeyEncryptor }
     *
     *
     */
    public List<CTKeyEncryptor> getKeyEncryptor() {
        if (keyEncryptor == null) {
            keyEncryptor = new ArrayList<CTKeyEncryptor>();
        }
        return this.keyEncryptor;
    }

}
