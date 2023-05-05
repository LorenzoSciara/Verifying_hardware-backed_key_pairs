package verifying_hardware_backed_key_pairs.com;

import androidx.appcompat.app.AppCompatActivity;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Ottieni il contesto dell'applicazione
        Context context = getApplicationContext();

// Ottieni il gestore delle chiavi
        KeyguardManager keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

// Ottieni l'alias della chiave
        String alias = "my_key_alias";

// Crea un oggetto di tipo KeyProperties per specificare le proprietà della chiave
        KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(30)
                .setRandomizedEncryptionRequired(false)
                .setIsStrongBoxBacked(true)
                .build();

// Genera la coppia di chiavi protetta da hardware
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        keyPairGenerator.initialize(keySpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

// Ottieni l'ID di attestazione della chiave
        KeyInfo keyInfo = keyStore.getKey(alias, null).getKeyInfo();
        long keyAttestationId = keyInfo.getAttestationChallenge();

// Invia una richiesta di attestazione della chiave al sistema operativo Android
        KeyAttestationRequest request = new KeyAttestationRequest.Builder()
                .setKeyAlias(alias)
                .setAttestationChallenge(keyAttestationId)
                .build();
        KeyAttestationManager keyAttestationManager = KeyAttestationManager.getInstance(context);
        KeyAttestationResult result = keyAttestationManager.attestKey(request);

// Verifica la risposta di attestazione
        if (result.getResultCode() == KeyAttestationResult.SUCCESS) {
            // La chiave è protetta da hardware e l'autenticità è stata verificata con successo
            AttestationRecord attestationRecord = result.getAttestationRecord();
            // Esegui ulteriori controlli di sicurezza sulla chiave e sulla risposta di attestazione
        } else {
            // La verifica dell'autenticità della chiave non è riuscita
        }


    }
}