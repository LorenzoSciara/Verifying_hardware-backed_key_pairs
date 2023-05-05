package com.example.myapplication;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        String ret;
        String alias = "my_key_alias"; // alias della coppia di chiavi
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        try {
            keyStore.load(null);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        PrivateKey privateKey = null;
        try {
            privateKey = (PrivateKey) keyStore.getKey(alias, null);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
        if (privateKey == null) {
            // la chiave privata non è presente nel KeyStore
            ret = "false";
        }

        KeyPair keyPair = null;
        try {
            keyPair = new KeyPair(keyStore.getCertificate(alias).getPublicKey(), privateKey);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        /*KeyAttestationUtils.AttestationResult attestationResult =
                KeyAttestationUtils.verifyKeyPairAttestation(keyPair, getApplicationContext());

        if (attestationResult == KeyAttestationUtils.AttestationResult.SUCCESS) {
            // la coppia di chiavi è hardware-backed
            return true;
        } else if (attestationResult == KeyAttestationUtils.AttestationResult.UNSUPPORTED_ALGORITHM) {
            // l'algoritmo della chiave non è supportato per Key Attestation
            return false;
        } else {
            // c'è stato un errore durante la verifica dell'attestazione
            return false;
        }*/
    }
}