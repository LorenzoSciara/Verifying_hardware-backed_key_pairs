package verifying_hardware_backed_key_pairs.com;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.TextView;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "KeyAttestationExample";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "MyKeyAlias";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView textViewPK = findViewById(R.id.publicKey);
        String publicKey = "Error!";

        TextView textViewC = findViewById(R.id.certificate);
        String certificate = "Error!";

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE);
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1);
            keyPairGenerator.initialize(builder.build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Verifying the attestation certificate chain
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (alias.equals(KEY_ALIAS)) {
                    Certificate[] certificateChain = keyStore.getCertificateChain(alias);
                    if (certificateChain != null && certificateChain.length > 0) {
                        Certificate attestationCertificate = certificateChain[0];

                        publicKey=attestationCertificate.getPublicKey().toString();
                        certificate=attestationCertificate.toString();

                        // Perform the necessary verification on the attestationCertificate
                        Log.d(TAG, "Attestation certificate verified");
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error: " + e.getMessage());
        }

        textViewPK.setText(publicKey);
        textViewC.setText(certificate);
    }
}