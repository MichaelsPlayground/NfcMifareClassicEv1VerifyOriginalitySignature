package de.androidcrypto.nfcmifareclassicev1verifyoriginalitysignature;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    EditText tagId, tagSignature, publicKeyNxp, readResult;
    private NfcAdapter mNfcAdapter;
    byte[] tagIdByte, tagSignatureByte, publicKeyByte;
    boolean signatureVerfied = false;

    final static String publicKeyNxpX = "494E1A386D3D3CFE3DC10E5DE68A499B";
    final static String publicKeyNxpY = "1C202DB5B132393E89ED19FE5BE8BC61";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tagId = findViewById(R.id.etVerifyTagId);
        tagSignature = findViewById(R.id.etVerifySignature);
        publicKeyNxp = findViewById(R.id.etVerifyPublicKey);
        readResult = findViewById(R.id.etVerifyResult);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        //publicKeyNxp.setText("04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61"); // NTAG21x
        //publicKeyNxp.setText("0490933bdcd6e99b4e255e3da55389a827564e11718e017292faf23226a96614b8"); // Ultralight EV1

        // taken from https://blog.linuxgemini.space/derive-pk-of-nxp-mifare-classic-ev1-ecdsa-signature
        publicKeyNxp.setText("044F6D3F294DEA5737F0F46FFEE88A356EED95695DD7E0C27A591E6F6F65962BAF"); // Mifare Classic EV1

    }

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {
        // Read and or write to Tag here to the appropriate Tag Technology type class
        // in this example the card should be an Ndef Technology Type

        System.out.println("NFC tag discovered");

        MifareClassic mfc = MifareClassic.get(tag);
        if (mfc == null) {
            runOnUiThread(() -> {
                Toast.makeText(getApplicationContext(),
                        "The tag is not readable with Mifare Classic classes, sorry",
                        Toast.LENGTH_SHORT).show();
            });
            return;
        }

        try {
            runOnUiThread(() -> {
                Toast.makeText(getApplicationContext(),
                        "NFC tag is Mifare Classic compatible",
                        Toast.LENGTH_SHORT).show();
                readResult.setText("");
                readResult.setBackgroundColor(getResources().getColor(R.color.white));
            });

            // Make a Sound
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
            } else {
                Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                v.vibrate(200);
            }

            mfc.connect();

            // tag ID
            tagIdByte = tag.getId();
            runOnUiThread(() -> {
                tagId.setText(Utils.bytesToHex(tagIdByte));
            });

            // see https://blog.linuxgemini.space/derive-pk-of-nxp-mifare-classic-ev1-ecdsa-signature
            // r can be read on PM3 with the command hf mf rdbl 69 B 4b791bea7bcc
            // s can be read on PM3 with the command hf mf rdbl 70 B 4b791bea7bcc
            byte[] r = readBlock(mfc, 69, Utils.hexStringToByteArray("4b791bea7bcc"));
            byte[] s = readBlock(mfc, 70, Utils.hexStringToByteArray("4b791bea7bcc"));
            if ((r == null) | (s == null)) {
                runOnUiThread(() -> {
                    Toast.makeText(getApplicationContext(),
                            "Error when reading the signature, aborted",
                            Toast.LENGTH_SHORT).show();
                    readResult.setText("Error when reading the signature, aborted");
                    return;
                });
            }

            System.out.println("*** ");
            if ((r != null) && (s != null)) {
                System.out.println("r length:" + r.length + " data: " + Utils.bytesToHex(r));
                System.out.println("s length:" + s.length + " data: " + Utils.bytesToHex(s));
            } else {
                System.out.println("r and/or s are null");
                return;
            }
            tagSignatureByte = new byte[32]; // length of the signature
            System.arraycopy(r, 0, tagSignatureByte, 0, r.length);
            System.arraycopy(s, 0, tagSignatureByte, 16, s.length);
            System.out.println("sig length:" + tagSignatureByte.length + " data: " + Utils.bytesToHex(tagSignatureByte));

            byte[] finalTagSignatureByte = tagSignatureByte;
            runOnUiThread(() -> {
                tagSignature.setText(Utils.bytesToHex(finalTagSignatureByte));
            });
        } catch (IOException e) {
            writeToUiAppend(readResult, "ERROR: IOException " + e.toString());
            e.printStackTrace();
        }

        // now we are going to verify
        // get the public key
        String publicKeyString = publicKeyNxp.getText().toString();
        try {
            signatureVerfied = checkEcdsaSignature(publicKeyString, tagSignatureByte, tagIdByte);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        writeToUiAppend(readResult, "SignatureVerified: " + signatureVerfied);
        runOnUiThread(() -> {
            if (signatureVerfied) {
                readResult.setBackgroundColor(getResources().getColor(R.color.light_background_green));
            } else {
                readResult.setBackgroundColor(getResources().getColor(R.color.light_background_red));
            }

        });
    }

    /**
     * read a single block from mifare classic tag by block
     *
     * @param mif
     * @param blockCnt
     * @param key      usually keyB for blocks outside the scope of user accessible memory
     * @return the content of block (16 bytes) or null if any error occurs
     */
    private byte[] readBlock(MifareClassic mif, int blockCnt, byte[] key) {
        byte[] block;
        int secCnt = mif.blockToSector(blockCnt);
        System.out.println("readBlock for block " + blockCnt + " is in sector " + secCnt);
        try {
            mif.authenticateSectorWithKeyB(secCnt, key);
            block = mif.readBlock(blockCnt);
        } catch (IOException e) {
            //throw new RuntimeException(e);
            System.out.println("RuntimeException: " + e.getMessage());
            return null;
        }
        return block;
    }

    // START code from NXP's AN11350 document (NTAG21x Originality Signature Validation)
    public static boolean checkEcdsaSignature(final String ecPubKey,
                                              final byte[]
                                                      signature, final byte[] data) throws NoSuchAlgorithmException {
        final ECPublicKeySpec ecPubKeySpec = getEcPubKey(ecPubKey,
                getEcSecp128r1());
        return checkEcdsaSignature(ecPubKeySpec, signature, data);
    }

    public static boolean checkEcdsaSignature(final ECPublicKeySpec
                                                      ecPubKey, final byte[]
                                                      signature, final byte[] data)
            throws NoSuchAlgorithmException {
        KeyFactory keyFac = null;
        try {
            keyFac = KeyFactory.getInstance("EC");
        } catch (final NoSuchAlgorithmException e1) {
            keyFac = KeyFactory.getInstance("ECDSA");
        }

        if (keyFac != null) {
            try {
                final PublicKey publicKey = keyFac.generatePublic(ecPubKey);
                final Signature dsa = Signature.getInstance("NONEwithECDSA");
                dsa.initVerify(publicKey);
                dsa.update(data);
                return dsa.verify(derEncodeSignature(signature));
            } catch (final SignatureException | InvalidKeySpecException | InvalidKeyException e) {
                e.printStackTrace();
            }
        }

        return false;
    }

    public static ECPublicKeySpec getEcPubKey(final String key, final
    ECParameterSpec
            curve) {
        if (key == null || key.length() != 2 * 33 || !key.startsWith("04")) {
            return null;
        }

        final String keyX = key.substring(2 * 1, 2 * 17);
        final String keyY = key.substring(2 * 17, 2 * 33);

        final BigInteger affineX = new BigInteger(keyX, 16);
        final BigInteger affineY = new BigInteger(keyY, 16);
        final ECPoint w = new ECPoint(affineX, affineY);

        return new ECPublicKeySpec(w, curve);
    }

    public static ECParameterSpec getEcSecp128r1() {
        // EC definition of "secp128r1":
        final BigInteger p = new
                BigInteger("fffffffdffffffffffffffffffffffff", 16);
        final ECFieldFp field = new ECFieldFp(p);

        final BigInteger a = new
                BigInteger("fffffffdfffffffffffffffffffffffc", 16);
        final BigInteger b = new
                BigInteger("e87579c11079f43dd824993c2cee5ed3", 16);
        final EllipticCurve curve = new EllipticCurve(field, a, b);

        final BigInteger genX = new
                BigInteger("161ff7528b899b2d0c28607ca52c5b86", 16);
        final BigInteger genY = new
                BigInteger("cf5ac8395bafeb13c02da292dded7a83", 16);
        final ECPoint generator = new ECPoint(genX, genY);

        final BigInteger order = new
                BigInteger("fffffffe0000000075a30d1b9038a115", 16);
        final int cofactor = 1;

        return new ECParameterSpec(curve, generator, order, cofactor);
    }

    public static byte[] derEncodeSignature(final byte[] signature) {
        // split into r and s
        final byte[] r = Arrays.copyOfRange(signature, 0, 16);
        final byte[] s = Arrays.copyOfRange(signature, 16, 32);

        int rLen = r.length;
        int sLen = s.length;
        if ((r[0] & 0x80) != 0) {
            rLen++;
        }
        if ((s[0] & 0x80) != 0) {
            sLen++;
        }
        final byte[] encodedSig = new byte[rLen + sLen + 6]; // 6 T and L bytes
        encodedSig[0] = 0x30; // SEQUENCE
        encodedSig[1] = (byte) (4 + rLen + sLen);
        encodedSig[2] = 0x02; // INTEGER
        encodedSig[3] = (byte) rLen;
        encodedSig[4 + rLen] = 0x02; // INTEGER
        encodedSig[4 + rLen + 1] = (byte) sLen;

        // copy in r and s
        encodedSig[4] = 0;
        encodedSig[4 + rLen + 2] = 0;
        System.arraycopy(r, 0, encodedSig, 4 + rLen - r.length, r.length);
        System.arraycopy(s, 0, encodedSig, 4 + rLen + 2 + sLen - s.length,
                s.length);

        return encodedSig;
    }
    // END code from NXP's AN11350 document (NTAG21x Originality Signature Validation)

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String newString = message + "\n" + textView.getText().toString();
            textView.setText(newString);
        });
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }
}