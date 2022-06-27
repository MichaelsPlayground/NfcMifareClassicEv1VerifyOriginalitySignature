package de.androidcrypto.nfcnfcaverifyntag21xsignature;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.NfcA;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
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

        publicKeyNxp.setText("04494E1A386D3D3C" +
                             "FE3DC10E5DE68A49" +
                             "9B1C202DB5B13239" +
                             "3E89ED19FE5BE8BC61");

        String publicKeyNxpX = "494E1A386D3D3CFE3DC10E5DE68A499B";
        String publicKeyNxpY = "1C202DB5B132393E89ED19FE5BE8BC61";

        //04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61
        // found in https://github.com/alexbatalov/node-nxp-originality-verifier/blob/master/index.js


        // Bouncy Castle version
        // this way for adding bouncycastle to android
        Security.removeProvider("BC");
        // Confirm that positioning this provider at the end works for your needs!
        Security.addProvider(new BouncyCastleProvider());
    }

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {
        // Read and or write to Tag here to the appropriate Tag Technology type class
        // in this example the card should be an Ndef Technology Type

        System.out.println("NFC tag discovered");

        NfcA nfcA = null;

        try {
            nfcA = NfcA.get(tag);
            if (nfcA != null) {
                runOnUiThread(() -> {
                    Toast.makeText(getApplicationContext(),
                            "NFC tag is Nfca compatible",
                            Toast.LENGTH_SHORT).show();
                });

                // Make a Sound
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
                } else {
                    Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                    v.vibrate(200);
                }

                runOnUiThread(() -> {
                    readResult.setText("");
                });

                nfcA.connect();

                // check that the tag is a NTAG213/215/216 manufactured by NXP - stop if not
                String ntagVersion = NfcIdentifyNtag.checkNtagType(nfcA, tag.getId());
                if (ntagVersion.equals("0")) {
                    runOnUiThread(() -> {
                        readResult.setText("NFC tag is NOT of type NXP NTAG213/215/216");
                        Toast.makeText(getApplicationContext(),
                                "NFC tag is NOT of type NXP NTAG213/215/216",
                                Toast.LENGTH_SHORT).show();
                    });
                    return;
                }

                // tag ID
                tagIdByte = tag.getId();
                runOnUiThread(() -> {
                    tagId.setText(Utils.bytesToHex(tagIdByte));
                });

                byte[] response = new byte[0];

                try {
                    String commandString = "3C00"; // read signature
                    byte[] commandByte = Utils.hexStringToByteArray(commandString);
                    try {
                        response = nfcA.transceive(commandByte); // response should be 16 bytes = 4 pages
                        if (response == null) {
                            // either communication to the tag was lost or a NACK was received
                            writeToUiAppend(readResult, "ERROR: null response");
                            return;
                        } else if ((response.length == 1) && ((response[0] & 0x00A) != 0x00A)) {
                            // NACK response according to Digital Protocol/T2TOP
                            // Log and return
                            writeToUiAppend(readResult, "ERROR: NACK response: " + Utils.bytesToHex(response));
                            return;
                        } else {
                            // success: response contains (P)ACK or actual data
                            writeToUiAppend(readResult, "SUCCESS: response: " + Utils.bytesToHex(response));
                            //System.out.println("write to page " + page + ": " + bytesToHex(response));
                            tagSignatureByte = response.clone();
                            runOnUiThread(() -> {
                                tagSignature.setText(Utils.bytesToHex(tagSignatureByte));
                            });
                        }
                    } catch (TagLostException e) {
                        // Log and return
                        System.out.println("*** TagLostException");
                        runOnUiThread(() -> {
                            readResult.setText("ERROR: Tag lost exception or command not recognized");
                        });
                        return;
                    } catch (IOException e) {
                        writeToUiAppend(readResult, "ERROR: IOException " + e.toString());
                        System.out.println("*** IOException");
                        e.printStackTrace();
                        return;
                    }
                } finally {
                    try {
                        nfcA.close();
                    } catch (IOException e) {
                        writeToUiAppend(readResult, "ERROR: IOException " + e.toString());
                        e.printStackTrace();
                    }
                }
            }
        } catch (IOException e) {
            writeToUiAppend(readResult, "ERROR: IOException " + e.toString());
            e.printStackTrace();
        }

        KeyFactory kf = null;
        PublicKey pubKey = null;
        publicKeyByte = Utils.hexStringToByteArray(publicKeyNxp.getText().toString());
        pubKey = getPublickKeyFromCompressed(publicKeyByte);
        if (pubKey == null) {
            writeToUiAppend(readResult, "ERROR on public key conversion");
            return;
        }
/*
        PublicKey pubKeyPoint = null;
        try {
            pubKeyPoint = pointToPublicKeyBC(publicKeyNxpX, publicKeyNxpY);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (pubKeyPoint == null) {
            writeToUiAppend(readResult, "ERROR on public key point conversion");
            return;
        } else {
            writeToUiAppend(readResult, "SUCCESS on public key point conversion");
        }
*/
        System.out.println("TAG signature validation");
        System.out.println("TagID: " + Utils.bytesToHex(tagIdByte));
        System.out.println("Signature length: " + tagSignatureByte.length);
        System.out.println("Signature: " + Utils.bytesToHex(tagSignatureByte));
        System.out.println("pubKey: " + Utils.bytesToHex(pubKey.getEncoded()));

/*
pubkey:
04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61
found in https://github.com/alexbatalov/node-nxp-originality-verifier/blob/master/index.js

data for locked NTAG216
I/System.out: TAG signature validation
I/System.out: TagID: 049e5082355b80
I/System.out: Signature length: 32
I/System.out: Signature: 6ce5a78347cdef508b13b66b35ac1ad6a25a7b1e36b8662012bf66d05716cb82
I/System.out: pubKey: 3036301006072a8648ce3d020106052b8104001c03220004494e1a386d3d3cfe3dc10e5de68a499b1c202db5b132393e89ed19fe5be8bc61
MDYwEAYHKoZIzj0CAQYFK4EEABwDIgAESU4aOG09PP49wQ5d5opJmxwgLbWxMjk+ie0Z/lvovGE=
data for unlocked NTAG216
I/System.out: TagID: 04408982355b81
I/System.out: Signature length: 32
I/System.out: Signature: 12650bfe759af5af5c42ae86b587c580f0b6cee5d25d4acfcbf3753f8fca0ec5
I/System.out: pubKey: 3036301006072a8648ce3d020106052b8104001c03220004494e1a386d3d3cfe3dc10e5de68a499b1c202db5b132393e89ed19fe5be8bc61
 */

        //System.out.println("pubKey point: " + Utils.bytesToHex(pubKeyPoint.getEncoded()));

        /*
        try {
            kf = KeyFactory.getInstance("ECDH");
            pubKey = (PublicKey) kf.generatePublic(new X509EncodedKeySpec(publicKeyByte));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
*/
        // now we are going to verify
        signatureVerfied = ecVerifySignatureP1363B(pubKey, tagIdByte, tagSignatureByte);
        writeToUiAppend(readResult, "SignatureVerified: " + signatureVerfied);

        // manual data from AN12196.pdf
        String tagIdX = "04518DFAA96180";
        String signatureRX = "D1940D17CFEDA4BFF80359AB975F9F6514313E8F90C1D3CAAF5941AD";
        String signatureSX = "744A1CDF9A83F883CAFE0FE95D1939B1B7E47113993324473B785D21";
        String pubXD = "8A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA";
        String pubYD = "209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410";
        // secp224r1


    }

    private static PublicKey getPublickKeyFromCompressed(byte[] compressedPublicKey) {

        KeyFactory keyFactory = null;
        try {
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp128r1");
            ECPoint point = ecSpec.getCurve().decodePoint(compressedPublicKey);
            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(point, ecSpec);
            keyFactory = KeyFactory.getInstance("ECDSA");
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }

    }

    public static PublicKey pointToPublicKeyBC(String x, String y) throws InvalidKeySpecException, NoSuchProviderException, NoSuchAlgorithmException {
        X9ECParameters ecp = SECNamedCurves.getByName("secp128r1");

        ECParameterSpec ecparam = new ECParameterSpec(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH());
        ECPoint ecPoint = ecp.getCurve().createPoint(new BigInteger(x, 16), new BigInteger(y, 16));
        ECPublicKeySpec spec = new ECPublicKeySpec(ecPoint, ecparam);

        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");
        PublicKey publicKey = keyFactory.generatePublic(spec);
        return publicKey;
    }

    private static Boolean ecVerifySignatureP1363(PublicKey publicKey, byte[] messageByte, byte[] signatureByte)
    {
        Signature publicSignature = null;
        try {
            //publicSignature = Signature.getInstance("SHA256withECDSAinP1363format");
            publicSignature = Signature.getInstance("SHA1withECDSAinP1363format", "BC");
            publicSignature.initVerify(publicKey);
            publicSignature.update(messageByte);
            return publicSignature.verify(signatureByte);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | NoSuchProviderException e) {
            e.printStackTrace();
            return false;
        }

    }

    private static Boolean ecVerifySignatureP1363B(PublicKey publicKey, byte[] messageByte, byte[] signatureByte)
    {
        Signature publicSignature = null;
        try {
            //publicSignature = Signature.getInstance("SHA256withECDSA");
            publicSignature = Signature.getInstance("SHA1withECDSA", "BC");
            publicSignature.initVerify(publicKey);
            publicSignature.update(messageByte);
            return publicSignature.verify((signatureByte));
            //return publicSignature.verify(P1363ToDer(signatureByte));
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | NoSuchProviderException e) {
            e.printStackTrace();
            return false;
        }
    }

    // conversions between Der to P1363 and vice versa
    // https://stackoverflow.com/a/61873962/8166854 answered May 18 '20 at 16:07 by dave_thompson_085
    // code is for SECP256R1
    // secp384r1 (aka P-384) has 384-bit order so use 384/8 which is 48 for n
    static byte[] P1363ToDer (byte[] p1363)  {
        //int n = 32; // for example assume 256-bit-order curve like P-256
        int n = 24;
        BigInteger r = new BigInteger (+1, Arrays.copyOfRange(p1363,0,n));
        BigInteger s = new BigInteger (+1, Arrays.copyOfRange(p1363,n,n*2));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r)); v.add(new ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded();
        } catch (IOException e) {
            e.printStackTrace();
            return new byte[0];
        }
    }

    static byte[] DerToP1363 (byte[] der) {
        int n = 32; // for example assume 256-bit-order curve like P-256
        BigInteger r, s;
        byte[] out;
        ASN1Sequence seq = ASN1Sequence.getInstance(der);
        r = ((ASN1Integer)seq.getObjectAt(0)).getValue();
        s = ((ASN1Integer)seq.getObjectAt(1)).getValue();
        out = new byte[2*n];
        toFixed(r, out, 0, n);
        toFixed(s, out, n, n);
        return out;
    }
    static void toFixed (BigInteger x, byte[] a, int off, int len) {
        byte[] t = x.toByteArray();
        if( t.length == len+1 && t[0] == 0 ) System.arraycopy (t,1, a,off, len);
        else if( t.length <= len ) System.arraycopy (t,0, a,off+len-t.length, t.length);
        else {
            System.exit(1);
        }
    }
    // end conversion der to p1363 and vice versa

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