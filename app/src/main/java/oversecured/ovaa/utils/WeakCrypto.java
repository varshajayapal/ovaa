package oversecured.ovaa.utils;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class WeakCrypto {

    private WeakCrypto() {
    }

    public static String encrypt(String data) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (!keyStore.containsAlias("ovaa_key")) {
                KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
                keyGen.init(new KeyGenParameterSpec.Builder("ovaa_key",
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build());
                keyGen.generateKey();
            }
            SecretKey key = (SecretKey) keyStore.getKey("ovaa_key", null);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] iv = cipher.getIV();
            byte[] cipherText = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            byte[] combined = ByteBuffer.allocate(iv.length + cipherText.length).put(iv).put(cipherText).array();
            return Base64.encodeToString(combined, Base64.NO_WRAP);
        } catch (Exception e) {
            return "";
        }
    }
}
