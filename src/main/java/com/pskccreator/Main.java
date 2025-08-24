package com.pskccreator;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.Base64;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.*;

public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Usage: java -jar pskc-creator.jar <input.csv>");
            return;
        }

        String csvFile = args[0];
        String outputFile = getOutputFileName(csvFile);

        List<String[]> tokens = readCSV(csvFile);
        Document xmlDoc = buildPSKC(tokens);
        writeXML(xmlDoc, outputFile);

        System.out.println("PSKC file generated: " + outputFile);
    }

    // Generate output filename based on input file (same name + .pskc.xml)
    private static String getOutputFileName(String csvFile) {
        String baseName = csvFile.replaceFirst("\\.[^.]+$", ""); // remove extension
        return baseName + ".pskc";
    }

    // Read CSV file and return tokens as String arrays
    private static List<String[]> readCSV(String csvFile) throws IOException {
        List<String[]> tokens = new ArrayList<>();
        List<String> lines = Files.readAllLines(Paths.get(csvFile));

        for (String line : lines) {
            if (line.trim().isEmpty() || line.startsWith("Serial")) continue;
            String[] parts = line.split(",");
            tokens.add(parts);
        }
        return tokens;
    }

    // Build PSKC XML document from token list
    private static Document buildPSKC(List<String[]> tokens) throws Exception {
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
        Document doc = docBuilder.newDocument();

        // Root element
        Element keyContainer = doc.createElement("KeyContainer");
        keyContainer.setAttribute("Version", "1.0");
        keyContainer.setAttribute("Id", "exampleContainer1");
        keyContainer.setAttribute("xmlns", "urn:ietf:params:xml:ns:keyprov:pskc");
        doc.appendChild(keyContainer);

        for (String[] token : tokens) {
            String serial = token[0];
            String hexSecret = token[1];
            String totpType = token[2];
            String length = token[3];
            String timestep = token[4];
            String issuer = token.length > 5 ? token[5] : "Unknown";

            // Convert hex secret → bytes → Base64
            byte[] secretBytes = hexStringToByteArray(hexSecret);
            String base64Secret = Base64.getEncoder().encodeToString(secretBytes);

            Element keyPackage = doc.createElement("KeyPackage");
            keyContainer.appendChild(keyPackage);

            // DeviceInfo
            Element deviceInfo = doc.createElement("DeviceInfo");
            keyPackage.appendChild(deviceInfo);

            Element manufacturer = doc.createElement("Manufacturer");
            manufacturer.setTextContent("Datablink");
            deviceInfo.appendChild(manufacturer);

            Element serialNo = doc.createElement("SerialNo");
            serialNo.setTextContent(serial);
            deviceInfo.appendChild(serialNo);

            Element model = doc.createElement("Model");
            model.setTextContent("SSV2");
            deviceInfo.appendChild(model);

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

            // Issuer
            Element issuerElem = doc.createElement("Issuer");
            issuerElem.setTextContent(issuer);
            keyElem.appendChild(issuerElem);

            // Data / Secret
            Element data = doc.createElement("Data");
            keyElem.appendChild(data);

            Element secret = doc.createElement("Secret");
            data.appendChild(secret);

            Element plainValue = doc.createElement("PlainValue");
            plainValue.setTextContent(base64Secret);
            secret.appendChild(plainValue);

            // TOTP parameters
            Element totp = doc.createElement("TOTP");
            totp.setAttribute("Algorithm", "SHA1");
            totp.setAttribute("Length", length);
            totp.setAttribute("TimeStep", timestep);
            data.appendChild(totp);
        }

        return doc;
    }

    // Write XML document to file
    private static void writeXML(Document doc, String filePath) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(filePath));
        transformer.transform(source, result);
    }

    // Convert hex string to byte array
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
