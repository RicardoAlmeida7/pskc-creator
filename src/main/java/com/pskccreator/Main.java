package com.pskccreator;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.*;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.Base64;

public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Usage: java -jar pskc-creator.jar <input.csv> [--encrypt]");
            return;
        }

        String csvFile = args[0];
        boolean encrypt = args.length > 1 && args[1].equalsIgnoreCase("--encrypt");

        String outputFile = getOutputFileName(csvFile, encrypt);
        List<String[]> tokens = readCSV(csvFile);

        byte[] preSharedKey = null;
        String preSharedKeyHex = null;

        if (encrypt) {
            // Generate a random 32-byte pre-shared key for encryption
            preSharedKey = new byte[32];
            new SecureRandom().nextBytes(preSharedKey);
            preSharedKeyHex = bytesToHex(preSharedKey);

            // Save the generated key to a separate file for distribution
            Path keyFile = Paths.get("preshared_key.txt");
            Files.write(keyFile, preSharedKeyHex.getBytes());
            System.out.println("Generated pre-shared key saved to: preshared_key.txt");
        }

        Document xmlDoc = buildPSKC(tokens, preSharedKey, encrypt);
        writeXML(xmlDoc, outputFile);

        System.out.println("PSKC file generated: " + outputFile);
        if (encrypt) {
            System.out.println("Encryption enabled: using generated pre-shared key");
        } else {
            System.out.println("Encryption disabled: secrets will be stored in plain Base64");
        }
    }

    private static String getOutputFileName(String csvFile, boolean encrypt) {
        String baseName = csvFile.replaceFirst("\\.[^.]+$", "");
        if (encrypt) {
            return baseName + "_encrypted.pskc";
        } else {
            return baseName + ".pskc";
        }
    }

    private static List<String[]> readCSV(String csvFile) throws IOException {
        List<String[]> tokens = new ArrayList<>();
        List<String> lines = Files.readAllLines(Paths.get(csvFile));
        for (String line : lines) {
            if (line.trim().isEmpty() || line.startsWith("Serial")) continue;
            tokens.add(line.split(","));
        }
        return tokens;
    }

    private static Document buildPSKC(List<String[]> tokens, byte[] preSharedKey, boolean encrypt) throws Exception {
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
        Document doc = docBuilder.newDocument();

        Element keyContainer = doc.createElement("KeyContainer");
        keyContainer.setAttribute("Version", "1.0");
        keyContainer.setAttribute("xmlns", "urn:ietf:params:xml:ns:keyprov:pskc");
        keyContainer.setAttribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
        keyContainer.setAttribute("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#");
        doc.appendChild(keyContainer);

        // Create EncryptionKey and MACMethod only if encryption is enabled
        byte[] macKeyBytes = null;
        if (encrypt) {
            // EncryptionKey element with KeyName
            Element encryptionKey = doc.createElement("EncryptionKey");
            appendTextElement(encryptionKey, "ds:KeyName", "Pre-shared-key");
            keyContainer.appendChild(encryptionKey);

            // MACMethod element
            Element macMethod = doc.createElement("MACMethod");
            macMethod.setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#hmac-sha1");
            Element macKey = doc.createElement("MACKey");

            macKeyBytes = new byte[20]; // HMAC-SHA1 = 20 bytes
            new SecureRandom().nextBytes(macKeyBytes);

            byte[] ivMac = new byte[16];
            new SecureRandom().nextBytes(ivMac);
            byte[] encMacKey = aesEncrypt(macKeyBytes, preSharedKey, ivMac);
            byte[] macCipherCombined = concat(ivMac, encMacKey);
            appendTextElement(macKey, "xenc:CipherData", Base64.getEncoder().encodeToString(macCipherCombined));

            Element macEncryptMethod = doc.createElement("xenc:EncryptionMethod");
            macEncryptMethod.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#aes128-cbc");
            macKey.appendChild(macEncryptMethod);
            macMethod.appendChild(macKey);
            keyContainer.appendChild(macMethod);
        }

        // Process each token
        for (String[] token : tokens) {
            String serial = token[0];
            String hexSecret = token[1];
            String totpType = token[2];
            String length = token[3];
            String timestep = token[4];
            String issuer = token.length > 5 ? token[5] : "Unknown";

            byte[] secretBytes = hexStringToByteArray(hexSecret);
            byte[] ivSecret = new byte[16];
            new SecureRandom().nextBytes(ivSecret);

            byte[] combinedSecret = null;
            byte[] valueMac = null;

            if (encrypt) {
                byte[] encryptedSecret = aesEncrypt(secretBytes, preSharedKey, ivSecret);
                combinedSecret = concat(ivSecret, encryptedSecret);
                valueMac = hmacSha1(macKeyBytes, combinedSecret);
            }

            // KeyPackage element
            Element keyPackage = doc.createElement("KeyPackage");
            keyContainer.appendChild(keyPackage);

            // DeviceInfo
            Element deviceInfo = doc.createElement("DeviceInfo");
            keyPackage.appendChild(deviceInfo);
            appendTextElement(deviceInfo, "Manufacturer", "Datablink");
            appendTextElement(deviceInfo, "SerialNo", serial);
            appendTextElement(deviceInfo, "Model", "SSV2");

            // CryptoModuleInfo
            Element cryptoModuleInfo = doc.createElement("CryptoModuleInfo");
            appendTextElement(cryptoModuleInfo, "Id", "CM_ID_001");
            keyPackage.appendChild(cryptoModuleInfo);

            // Key element
            Element keyElem = doc.createElement("Key");
            keyElem.setAttribute("Id", serial);
            keyElem.setAttribute("Algorithm", "urn:ietf:params:xml:ns:keyprov:pskc:" + totpType.toLowerCase());
            keyPackage.appendChild(keyElem);

            // AlgorithmParameters
            Element algoParams = doc.createElement("AlgorithmParameters");
            keyElem.appendChild(algoParams);
            Element responseFormat = doc.createElement("ResponseFormat");
            responseFormat.setAttribute("Encoding", "DECIMAL");
            responseFormat.setAttribute("Length", length);
            algoParams.appendChild(responseFormat);

            appendTextElement(keyElem, "Issuer", issuer);

            // Data
            Element data = doc.createElement("Data");
            keyElem.appendChild(data);

            // Secret
            Element secret = doc.createElement("Secret");
            data.appendChild(secret);

            if (encrypt) {
                Element encryptedValue = doc.createElement("EncryptedValue");
                Element encMethod = doc.createElement("xenc:EncryptionMethod");
                encMethod.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#aes128-cbc");
                encryptedValue.appendChild(encMethod);

                Element cipherData = doc.createElement("xenc:CipherData");
                appendTextElement(cipherData, "xenc:CipherValue", Base64.getEncoder().encodeToString(combinedSecret));
                encryptedValue.appendChild(cipherData);
                secret.appendChild(encryptedValue);

                appendTextElement(secret, "ValueMAC", Base64.getEncoder().encodeToString(valueMac));
            } else {
                appendTextElement(secret, "PlainValue", Base64.getEncoder().encodeToString(secretBytes));
            }

            // Counter
            Element counter = doc.createElement("Counter");
            appendTextElement(counter, "PlainValue", "0");
            data.appendChild(counter);

            // TOTP
            Element totp = doc.createElement("TOTP");
            totp.setAttribute("Algorithm", "SHA1");
            totp.setAttribute("Length", length);
            totp.setAttribute("TimeStep", timestep);
            data.appendChild(totp);
        }

        return doc;
    }

    private static void appendTextElement(Element parent, String name, String text) {
        Element elem = parent.getOwnerDocument().createElement(name);
        elem.setTextContent(text);
        parent.appendChild(elem);
    }

    private static void writeXML(Document doc, String filePath) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(filePath));
        transformer.transform(source, result);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    private static byte[] aesEncrypt(byte[] data, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(key, 0, 16, "AES"); // AES-128
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
        return cipher.doFinal(data);
    }

    private static byte[] hmacSha1(byte[] key, byte[] data) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
