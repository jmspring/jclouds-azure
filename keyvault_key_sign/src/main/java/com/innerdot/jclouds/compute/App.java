package com.innerdot.jclouds.compute;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.inject.Module;
import com.google.common.hash.Hashing;

import com.nimbusds.jose.jwk.RSAKey;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.jclouds.ContextBuilder;
import org.jclouds.azurecompute.arm.AzureComputeApi;
import org.jclouds.azurecompute.arm.domain.Key;
import org.jclouds.azurecompute.arm.domain.SKU;
import org.jclouds.azurecompute.arm.domain.Vault;
import org.jclouds.azurecompute.arm.domain.VaultProperties;
import org.jclouds.azurecompute.arm.features.VaultApi;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.jclouds.sshj.config.SshjSshClientModule;

import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import javax.xml.bind.DatatypeConverter;

public class App
{
    // Provider to use
    private static final String provider = "azurecompute-arm";

    // Required properties for Azure provider
    public static final String PROPERTY_AZURE_TENANT_ID = "azurecompute-arm.tenantId";
    public static final String PROPERTY_AZURE_SUBSCRIPTION_ID = "azurecompute-arm.subscriptionId";

    private static RSAPublicKey getPublicKey(byte[] keyBytes) { PublicKey publicKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            publicKey = kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("Parsing public key failed.  Algorithm not supported.  Error: " + nsae.toString());
        } catch (InvalidKeySpecException ikse) {
            System.out.println("Unable to parse public key.  Invalid spec.  Error: " + ikse.toString());
        }
        return (RSAPublicKey)publicKey;
    }

    private static RSAPrivateKey getPrivateKey(byte[] keyBytes) {
        PrivateKey privateKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            privateKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("Parsing private key failed.  Algorithm not supported.  Error: " + nsae.toString());
        } catch (InvalidKeySpecException ikse) {
            System.out.println("Unable to parse private key.  Invalid spec.  Error: " + ikse.toString());
        }
        return (RSAPrivateKey)privateKey;
    }

    public static void main( String[] args )
    {
        // Retrieve necessary config information
        if(args.length != 10) {
            System.out.println("Usage: <principal ID> <principal secret> <resouce group> <tenand ID> " +
                    "<subscription ID> <region> <keyVault name> <private key file> <public key file> <string to sign>");
            System.exit(1);
        }

        final String clientId = args[0];
        final String clientPassword = args[1];
        final String resourceGroup = args[2];
        final String tenantId = args[3];
        final String subscriptionId = args[4];
        final String region = args[5];
        final String vaultName = args[6];
        final String privateKeyFile = args[7];
        final String publicKeyFile = args[8];
        final String stringToSign = args[9];
        final String keyName = "testKey";

        // For this example, the private and public key RSA PEMs are loaded
        // and converte into a JSON Webkey which is ued by Azure KeyVault
        RSAPrivateKey privateKey = null;
        RSAPublicKey publicKey = null;
        try {
            // read the private key
            final PemReader privReader = new PemReader(new FileReader(privateKeyFile));
            PemObject pemObject = privReader.readPemObject();
            privateKey = getPrivateKey(pemObject.getContent());

            final PemReader pubReader = new PemReader(new FileReader(publicKeyFile));
            pemObject = pubReader.readPemObject();
            publicKey = getPublicKey(pemObject.getContent());
        } catch(java.io.IOException ioe) {
            System.out.println("IO Exception: " + ioe.toString());
        }
        if(privateKey == null) {
            System.out.println("Unable to load private key: " + privateKeyFile);
            System.exit(1);
        } else if(publicKey == null) {
            System.out.println("Unable to load public key: " + publicKeyFile);
            System.exit(1);

        }
        RSAKey keyJwt = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .build();

        // Set properties to be used by provider.  The azurecompute-arm provider
        // relies internally on these values being set as properties
        final ImmutableMap<String, String> azureProperties = ImmutableMap.of(
                PROPERTY_AZURE_SUBSCRIPTION_ID, subscriptionId,
                PROPERTY_AZURE_TENANT_ID, tenantId
        );
        Properties properties = new Properties();
        properties.putAll(azureProperties);

        // Modules needed for setup -- logging and so JClouds can SSH into the VM and set things up
        Iterable<Module> modules = ImmutableSet.<Module> of(
                new SshjSshClientModule(),
                new SLF4JLoggingModule()
        );

        // Get access to the AzureComputeAPI using the ContextBuilder then return an instance of the VaultApi.
        AzureComputeApi azureClient = ContextBuilder.newBuilder(provider)
                .credentials(clientId, clientPassword)
                .modules(modules)
                .overrides(properties)
                .buildApi(AzureComputeApi.class);
        VaultApi vaultApi = azureClient.getVaultApi(resourceGroup);

        // Create the KeyVault.  Creating a KeyVault has a number of components to
        // it including access policy by entity -- for certs, keys, secrets, etc.
        String objectId = azureClient.getServicePrincipal().get().objectId();
        Vault vault = vaultApi.createOrUpdateVault(vaultName, region, VaultProperties.builder()
                        .tenantId(tenantId)
                        .sku(SKU.create(region, "standard", null, "A"))
                        .accessPolicies(ImmutableList.of(VaultProperties.AccessPolicyEntry.create(null, objectId, tenantId,
                                VaultProperties.Permissions.create(
                                        ImmutableList.<String>of(),
                                        ImmutableList.of( // keys
                                                "Get",
                                                "List",
                                                "Update",
                                                "Import",
                                                "Delete",
                                                "Sign",
                                                "Verify"
                                        ),
                                        ImmutableList.<String>of(),
                                        ImmutableList.<String>of()
                                ))))
                        .build(),
                null);

        // Import the key into the KeyVault
        Key.KeyAttributes keyAttr = Key.KeyAttributes.create(true, null, null, null, null, null);
        List<String> keyOps = new ArrayList<String>();
        keyOps.add("sign");
        keyOps.add("verify");
        Key.JsonWebKey keyInfo = Key.JsonWebKey.create(
                null,
                keyJwt.getPrivateExponent().toString(),
                keyJwt.getFirstFactorCRTExponent().toString(),
                keyJwt.getSecondFactorCRTExponent().toString(),
                keyJwt.getPublicExponent().toString(),
                null,
                null,
                keyOps,
                null,
                "RSA",
                keyJwt.getModulus().toString(),
                keyJwt.getFirstPrimeFactor().toString(),
                keyJwt.getSecondPrimeFactor().toString(),
                keyJwt.getFirstCRTCoefficient().toString(),
                null,
                null
        );
        Key.KeyBundle importedKey = vaultApi.importKey(vault.properties().vaultUri(), keyName, false, keyAttr, keyInfo, null);
        if(importedKey == null) {
            System.out.println("Failed to import key.");
            System.exit(1);
        }

        // When "signing" using an RSA key, the data size is limited to a maximum block size.  Often
        // "signing" is down on the hash of the content that is to be "signed".  For this example,
        // we will sign the SHA-256 hash of the content provided.
        String contentHash = Hashing.sha256()
                .hashString(stringToSign, StandardCharsets.UTF_8)
                .toString();
        Key.KeyOperationResult signResult = vaultApi.sign(
                vault.properties().vaultUri(),
                keyName,
                "",
                "RS256",
                contentHash
        );
        if(signResult == null) {
            System.out.println("Failed to sign hash.");
            System.exit(1);
        }

        // Result of signing
        System.out.println("Sign result: " + signResult.value());
    }
}
