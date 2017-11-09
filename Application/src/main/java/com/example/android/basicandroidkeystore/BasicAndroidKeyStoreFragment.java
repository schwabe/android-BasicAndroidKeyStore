/*
* Copyright (C) 2013 The Android Open Source Project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package com.example.android.basicandroidkeystore;

import com.example.android.common.logger.Log;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.util.Base64;
import android.view.MenuItem;
import android.widget.Toast;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.security.auth.x500.X500Principal;

public class BasicAndroidKeyStoreFragment extends Fragment {

    public static final String TAG = "KeyStoreFragment";

    // BEGIN_INCLUDE(values)

    public static final String SAMPLE_ALIAS = "myKey";

    // Some sample data to sign, and later verify using the generated signature.
    public static final String SAMPLE_INPUT = "Hello, Android!";

    // Just a handy place to store the signature in between signing and verifying.
    public String mSignatureStr = null;

    // You can store multiple key pairs in the Key Store.  The string used to refer to the Key you
    // want to store, or later pull, is referred to as an "alias" in this case, because calling it
    // a key, when you use it to retrieve a key, would just be irritating.
    private String mAlias = null;

    // END_INCLUDE(values)

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setHasOptionsMenu(true);
        setAlias(SAMPLE_ALIAS);
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.btn_select_key:
                KeyChain.choosePrivateKeyAlias(getActivity(), new KeyChainAliasCallback() {
                    @Override
                    public void alias(@Nullable String alias) {
                        mAlias = alias;
                    }
                }, null, null, "fakehost", -1, mAlias);

                return true;
            case R.id.btn_sign_data:
                new Thread(new Runnable() {
                    @Override
                    public void run() {

                        try {
                            mSignatureStr = signData(SAMPLE_INPUT);
                        } catch (KeyStoreException e) {
                            Log.w(TAG, "KeyStore not Initialized", e);
                        } catch (UnrecoverableEntryException e) {
                            Log.w(TAG, "KeyPair not recovered", e);
                            e.printStackTrace();
                        } catch (NoSuchAlgorithmException e) {
                            Log.w(TAG, "RSA not supported", e);
                        } catch (InvalidKeyException e) {
                            Log.w(TAG, "Invalid Key", e);
                        } catch (SignatureException e) {
                            Log.w(TAG, "Invalid Signature", e);
                        } catch (IOException e) {
                            Log.w(TAG, "IO Exception", e);
                        } catch (CertificateException e) {
                            Log.w(TAG, "Error occurred while loading certificates", e);
                            e.printStackTrace();
                        } catch (InterruptedException e) {
                            Log.w(TAG, "Error occurred while loading certificates", e);
                            e.printStackTrace();
                        } catch (KeyChainException e) {
                            Log.w(TAG, "Error occurred while loading certificates", e);
                            e.printStackTrace();
                        }
                        Log.d(TAG, "Signature: " + mSignatureStr);

                    }
                }).start();
                return true;

            case R.id.btn_verify_data:
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        boolean verified = false;
                        try {
                            if (mSignatureStr != null) {
                                verified = verifyData(SAMPLE_INPUT, mSignatureStr);
                            }
                        } catch (KeyStoreException e) {
                            Log.w(TAG, "KeyStore not Initialized", e);
                        } catch (CertificateException e) {
                            Log.w(TAG, "Error occurred while loading certificates", e);
                        } catch (NoSuchAlgorithmException e) {
                            Log.w(TAG, "RSA not supported", e);
                        } catch (IOException e) {
                            Log.w(TAG, "IO Exception", e);
                        } catch (UnrecoverableEntryException e) {
                            Log.w(TAG, "KeyPair not recovered", e);
                        } catch (InvalidKeyException e) {
                            Log.w(TAG, "Invalid Key", e);
                        } catch (SignatureException e) {
                            Log.w(TAG, "Invalid Signature", e);
                        } catch (InterruptedException e) {
                            Log.w(TAG, "Error occurred while loading certificates", e);
                        } catch (KeyChainException e) {
                            Log.w(TAG, "Error occurred while loading certificates", e);
                        }
                        if (verified) {
                            Log.d(TAG, "Data Signature Verified");
                        } else {
                            Log.d(TAG, "Data not verified.");
                        }
                    }
                }).start();
                return true;

            case R.id.btn_import_asset:

                String client_p12 = "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";
                byte[] pkcs12data = Base64.decode(client_p12, Base64.DEFAULT);

                Intent i = KeyChain.createInstallIntent();
                i.putExtra(KeyChain.EXTRA_PKCS12, pkcs12data);
                i.putExtra(KeyChain.EXTRA_NAME, "client");
                startActivity(i);
                Toast.makeText(getActivity(), "Use password as password", Toast.LENGTH_LONG).show();
                return true;
        }
        return false;
    }

    /**
     * Creates a public and private key and stores it using the Android Key Store, so that only
     * this application will be able to access the keys.
     */
    public void createKeys(Context context) throws NoSuchProviderException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // BEGIN_INCLUDE(create_valid_dates)
        // Create a start and end time, for the validity range of the key pair that's about to be
        // generated.
        Calendar start = new GregorianCalendar();
        Calendar end = new GregorianCalendar();
        end.add(Calendar.YEAR, 1);
        //END_INCLUDE(create_valid_dates)

        // BEGIN_INCLUDE(create_keypair)
        // Initialize a KeyPair generator using the the intended algorithm (in this example, RSA
        // and the KeyStore.  This example uses the AndroidKeyStore.
        KeyPairGenerator kpGenerator = KeyPairGenerator
                .getInstance(SecurityConstants.TYPE_RSA,
                        SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
        // END_INCLUDE(create_keypair)

        // BEGIN_INCLUDE(create_spec)
        // The KeyPairGeneratorSpec object is how parameters for your key pair are passed
        // to the KeyPairGenerator.
        AlgorithmParameterSpec spec;

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            // Below Android M, use the KeyPairGeneratorSpec.Builder.

            spec = new KeyPairGeneratorSpec.Builder(context)
                    // You'll use the alias later to retrieve the key.  It's a key for the key!
                    .setAlias(mAlias)
                    // The subject used for the self-signed certificate of the generated pair
                    .setSubject(new X500Principal("CN=" + mAlias))
                    // The serial number used for the self-signed certificate of the
                    // generated pair.
                    .setSerialNumber(BigInteger.valueOf(1337))
                    // Date range of validity for the generated pair.
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();


        } else {
            // On Android M or above, use the KeyGenparameterSpec.Builder and specify permitted
            // properties  and restrictions of the key.
            spec = new KeyGenParameterSpec.Builder(mAlias, KeyProperties.PURPOSE_SIGN)
                    .setCertificateSubject(new X500Principal("CN=" + mAlias))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setCertificateSerialNumber(BigInteger.valueOf(1337))
                    .setCertificateNotBefore(start.getTime())
                    .setCertificateNotAfter(end.getTime())
                    .build();
        }

        kpGenerator.initialize(spec);

        KeyPair kp = kpGenerator.generateKeyPair();
        // END_INCLUDE(create_spec)
        Log.d(TAG, "Public Key is: " + kp.getPublic().toString());
    }

    /**
     * Signs the data using the key pair stored in the Android Key Store.  This signature can be
     * used with the data later to verify it was signed by this application.
     *
     * @return A string encoding of the data signature generated
     */
    public String signData(String inputStr) throws KeyStoreException,
            UnrecoverableEntryException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, IOException, CertificateException, KeyChainException, InterruptedException {
        byte[] data = inputStr.getBytes();

        /*
        // BEGIN_INCLUDE(sign_load_keystore)
        KeyStore ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);

        // Weird artifact of Java API.  If you don't have an InputStream to load, you still need
        // to call "load", or it'll crash.
        ks.load(null);

        // Load the key pair from the Android Key Store
        KeyStore.Entry entry = ks.getEntry(mAlias, null);
        */

        PrivateKey privatekey = null;
        privatekey = KeyChain.getPrivateKey(getActivity(), mAlias);


        /* If the entry is null, keys were never stored under this alias.
         * Debug steps in this situation would be:
         * -Check the list of aliases by iterating over Keystore.aliases(), be sure the alias
         *   exists.
         * -If that's empty, verify they were both stored and pulled from the same keystore
         *   "AndroidKeyStore"
         */
        if (privatekey == null) {
            Log.w(TAG, "No key found under alias: " + mAlias);
            Log.w(TAG, "Exiting signData()...");
            return null;
        }


        // BEGIN_INCLUDE(sign_create_signature)
        // This class doesn't actually represent the signature,
        // just the engine for creating/verifying signatures, using
        // the specified algorithm.
        Signature s = Signature.getInstance(SecurityConstants.SIGNATURE_SHA256withRSA);

        // Initialize Signature using specified private key
        s.initSign(privatekey);

        // Sign the data, store the result as a Base64 encoded String.
        s.update(data);
        byte[] signature = s.sign();
        String result = Base64.encodeToString(signature, Base64.DEFAULT);
        // END_INCLUDE(sign_data)

        return result;
    }

    /**
     * Given some data and a signature, uses the key pair stored in the Android Key Store to verify
     * that the data was signed by this application, using that key pair.
     *
     * @param input        The data to be verified.
     * @param signatureStr The signature provided for the data.
     * @return A boolean value telling you whether the signature is valid or not.
     */
    public boolean verifyData(String input, String signatureStr) throws KeyStoreException,
            CertificateException, NoSuchAlgorithmException, IOException,
            UnrecoverableEntryException, InvalidKeyException, SignatureException, KeyChainException, InterruptedException {
        byte[] data = input.getBytes();
        byte[] signature;
        // BEGIN_INCLUDE(decode_signature)

        // Make sure the signature string exists.  If not, bail out, nothing to do.

        if (signatureStr == null) {
            Log.w(TAG, "Invalid signature.");
            Log.w(TAG, "Exiting verifyData()...");
            return false;
        }

        try {
            // The signature is going to be examined as a byte array,
            // not as a base64 encoded string.
            signature = Base64.decode(signatureStr, Base64.DEFAULT);
        } catch (IllegalArgumentException e) {
            // signatureStr wasn't null, but might not have been encoded properly.
            // It's not a valid Base64 string.
            return false;
        }
        // END_INCLUDE(decode_signature)

        // Load the key pair from the Android Key Store
        X509Certificate[] certchain = null;
        certchain = KeyChain.getCertificateChain(getActivity(), mAlias);


        if (certchain == null) {
            Log.w(TAG, "No cert found under alias: " + mAlias);
            Log.w(TAG, "Exiting verifyData()...");
            return false;
        }

        // This class doesn't actually represent the signature,
        // just the engine for creating/verifying signatures, using
        // the specified algorithm.
        Signature s = Signature.getInstance(SecurityConstants.SIGNATURE_SHA256withRSA);

        // BEGIN_INCLUDE(verify_data)
        // Verify the data.
        s.initVerify(certchain[0]);
        s.update(data);
        return s.verify(signature);
        // END_INCLUDE(verify_data)
    }

    public void setAlias(String alias) {
        mAlias = alias;
    }
}
