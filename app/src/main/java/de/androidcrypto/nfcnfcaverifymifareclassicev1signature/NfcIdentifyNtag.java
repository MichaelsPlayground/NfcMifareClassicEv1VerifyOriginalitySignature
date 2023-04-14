package de.androidcrypto.nfcnfcaverifymifareclassicev1signature;

import android.nfc.tech.NfcA;

import java.io.IOException;
import java.util.Arrays;

public class NfcIdentifyNtag {

    private static String identifiedNtagType = ""; // NTAG213, NTAG215 or NTAG216
    private static int identifiedNtagPages = 0; // NTAG 213 = 36, 215 = 126, 216 = 222 pages
    private static int identifiedNtagMemoryBytes = 0; // NTAG 213 = 144, 215 = 504, 216 = 888 bytes
    private static byte[] identifiedNtagId = new byte[0];

    // data show here are from NXP NTAG21x data sheet
    private static byte[] ntag213VersionData = new byte[]{
            (byte) 0x00, // fixed header
            (byte) 0x04, // vendor ID, 04h = NXP
            (byte) 0x04, // product type = NTAG
            (byte) 0x02, // product subtype = 50 pF
            (byte) 0x01, // major product version 1
            (byte) 0x00, // minor product version V0
            (byte) 0x0F, // storage size = 144 bytes
            (byte) 0x03  // protocol type = ISO/IEC 14443-3 compliant
    };
    private static byte[] ntag215VersionData = new byte[]{
            (byte) 0x00, // fixed header
            (byte) 0x04, // vendor ID, 04h = NXP
            (byte) 0x04, // product type = NTAG
            (byte) 0x02, // product subtype = 50 pF
            (byte) 0x01, // major product version 1
            (byte) 0x00, // minor product version V0
            (byte) 0x11, // storage size = 504 bytes
            (byte) 0x03  // protocol type = ISO/IEC 14443-3 compliant
    };
    private static byte[] ntag216VersionData = new byte[]{
            (byte) 0x00, // fixed header
            (byte) 0x04, // vendor ID, 04h = NXP
            (byte) 0x04, // product type = NTAG
            (byte) 0x02, // product subtype = 50 pF
            (byte) 0x01, // major product version 1
            (byte) 0x00, // minor product version V0
            (byte) 0x13, // storage size = 888 bytes
            (byte) 0x03  // protocol type = ISO/IEC 14443-3 compliant
    };

    // returns 213/215/216 if tag is found or 0 when not detected
    public static String checkNtagType(NfcA nfca, byte[] ntagId) {
        clearInternalData();
        String returnCode = "0";
        identifiedNtagId = ntagId;
        byte[] response;
        // first we are checking that the tag is produced by NXP
        // Get Page 00h
        // reads 16 bytes = 4 pages in one run
        try {
            response = nfca.transceive(new byte[]{
                    (byte) 0x30, // READ
                    (byte) 0x00  // page address
            });
            // only check for byte 00 - 04h means NXP...
            byte[] uid0 = Arrays.copyOfRange(response, 0, 1);
            //nfcaContentString = nfcaContentString + "\n" + " Uid pos 00: " + bytesToHex(uid0);
            if (!Arrays.equals(uid0, new byte[]{(byte) 0x04})) {
                return returnCode; // not produced by NXP
            }
            // get version
            response = nfca.transceive(new byte[] {
                    (byte) 0x60 // GET VERSION
            });
            if (Arrays.equals(response, ntag213VersionData)) {
                returnCode = "213";
                identifiedNtagType = "NTAG213";
                identifiedNtagPages = 36;
                identifiedNtagMemoryBytes = 144;
            }
            if (Arrays.equals(response, ntag215VersionData)) {
                returnCode = "215";
                identifiedNtagType = "NTAG215";
                identifiedNtagPages = 126;
                identifiedNtagMemoryBytes = 504;
            }
            if (Arrays.equals(response, ntag216VersionData)) {
                returnCode = "216";
                identifiedNtagType = "NTAG216";
                identifiedNtagPages = 222;
                identifiedNtagMemoryBytes = 888;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return returnCode;
    }

    public static String getIdentifiedNtagType() {
        return identifiedNtagType;
    }

    public static int getIdentifiedNtagPages() {
        return identifiedNtagPages;
    }

    public static int getIdentifiedNtagMemoryBytes() { return identifiedNtagMemoryBytes; }

    public static byte[] getIdentifiedNtagId() { return identifiedNtagId; }

    public static void clearInternalData() {
        identifiedNtagType = "";
        identifiedNtagPages = 0;
        identifiedNtagMemoryBytes = 0;
        identifiedNtagId = new byte[0];
    }

}
