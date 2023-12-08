import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.AlgorithmParameters;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DecryptorLogic {
    private Properties properties = new Properties();
    private String symmetricEncryptionAlg;
    private String symmetricEncryptionProvider;
    private String signatureAlg;
    private String signatureProvider;
    private String asymmetricEncryptionAlgForKey;
    private String asymmetricEncryptionProviderForKey;    
    private DecryptorUserInput userInput;
    private KeyStore keyStore;
    private Cipher cipher;
    private char[] passwordKeyStore;
    private char[] passwordPrivateKey;
    private AlgorithmParameters algParameters;

    /**
     * Constructs a new instance of this logic class
     * With 2 passwords - one for the whole keystore and one for the user's private key
     * and a path to the User-Input file.
     * We HIGHLY RECOMMEND the client of this class to take the passwords by command-line input
     * and never save them on any file or in the code itself!
     * 
     * @param passwordKeyStore - the password for protecting the integrity of the whole keystore
     * @param passwordPrivateKey - the password for protecting the secrecy of the user's private key
     * @param userInputFilePath - the path to the User-Input file
     */
    public DecryptorLogic(char[] passwordKeyStore, char[] passwordPrivateKey, String userInputFilePath){
        this.passwordKeyStore = passwordKeyStore;
        this.passwordPrivateKey = passwordPrivateKey;
        this.userInput = new DecryptorUserInput(userInputFilePath);
    }

    /**
     * The public API this class exposes to this class' client:
     * Verifies the integrity and authenticity of the given encrypted file
     * by verifying its "assymetric" digital signature (loaded from the given configuration file).
     * 
     * If the integrity check is valid, decrypts to a file of a given path the encrypted file hibridly:
     *   Assymetrically the symmetric key from the configuration file in a given path
     *   and then symmetrically the file from a given path
     * with all the parameters given by the user in the User-Input file
     * (mentioned in the User-Input file).
     *
     * @throws Exception
     */
    public void verifyAndDecrypt() throws Exception{
        userInput.init();
        loadConfigFromFile();
        loadKeyStore();
        boolean isVerified = verifyEncryptedFile();
        if (isVerified){
            decryptHybridlyFile();
        }
    }

    /**
     * Loads the properties from the configuration file in the path given by the user in the User-Input file
     * NOTE: This configuration file was created by the Encryptor program and contains parameters used for the
     * encryption, needed for the decryption.
     * Although, the user of the Decryptor Program (uses this logic class) may change the providers (except the keystore's),
     * and thanks to implementation independence and interoperability the decryption still works.
     * 
     * @throws Exception
     */
    private void loadConfigFromFile() throws Exception {
        try (FileInputStream fis = new FileInputStream(userInput.getInputConfigFilePath())) {
            this.properties.load(fis);
            this.symmetricEncryptionAlg = this.properties.getProperty("symmetricEncryptionAlg");
            this.symmetricEncryptionProvider = this.properties.getProperty("symmetricEncryptionProvider", "");
            this.signatureAlg = this.properties.getProperty("signatureAlg");
            this.signatureProvider = this.properties.getProperty("signatureProvider", "");
            this.asymmetricEncryptionAlgForKey = this.properties.getProperty("asymmetricEncryptionAlgForKey");
            this.asymmetricEncryptionProviderForKey = this.properties.getProperty("asymmetricEncriptionProviderForKey", "");
        } catch (Exception exception) {
            throw exception;
        }
    }
    
    /**
     * Loads from the configuration file the AlgorithmParameters used by the Encryptor Program
     * to the data member algParameters for the given decryption algorithm,
     * which its name is given in algName.
     * Excpects this input to be formated in Base64.
     * 
     * @param algName - the name of the decryption algorithm
     * @throws Exception
     */
    private void loadAlgParamsFromConfigFile(String algName) throws Exception {
        byte[] algParametersBytes = Base64.getDecoder().decode(this.properties.getProperty("algParameters"));
        algParameters = AlgorithmParameters.getInstance(algName);
        algParameters.init(algParametersBytes);
    }

    /**
     * Loads the keystore located in the path given by the user in the User-Input file
     * with its password is given by the user in the command line.
     * 
     * We used the KeyStore engine class which can load a keystore from the storage.
     * the KsyStore instance is created with its type, given by the user in the User-Input file.
     * If a provider was suplied by the user in the User-Input file as well, so it's loaded 
     * with this provider. Otherwise it uses the system's default provider.
     * 
     * @throws Exception
     */
    private void loadKeyStore() throws Exception {
        try (FileInputStream fis = new FileInputStream(userInput.getKeyStorePathB())) {
            keyStore = userInput.getKeyStoreProvider().equals("") ?
                KeyStore.getInstance(userInput.getKeyStoreType()) :
                    KeyStore.getInstance(userInput.getKeyStoreType(), userInput.getKeyStoreProvider());
            keyStore.load(fis, passwordKeyStore);
        } catch (Exception exception) {
            throw exception;
        }
    }

    /**
     * Verifies the integrity and authenticity of the encrypted file, stored in a path given by the user in the User-Input file
     * by verifying the digital signature on the encrypted file, stored in the configuration file.
     * 
     * This is done by extracting the public key of the sender (side A) from his/her certificate
     * which is stored as a trusted certificate in the user's (side B) keystore, by its alias given by the user in the User-Input file.
     * Thus, we use the appropriate engine classes Certificate and PublicKey.
     * 
     * Then we instantiate a Signature engine class instance with the signature algorithm specified in the
     * configuration file generated by the Encryptor Program.
     * If a provider is suplied in the configuration file it uses it as well, otherwise it uses the default provider.
     * We init the Signature instance with side A's public key, which is supposed to match side A's private key
     * which was used when side A signed the encrypted file.
     * 
     * We update the Signature instance with the bytes of the cipher text from the encrypted file,
     * and then verify the digital siganture.
     * The outcome (verification succeeded / failed) is returned by this method as a boolean.
     * 
     * In addition - if verification failed, an appropriate message is displayed to the console and to the output file,
     * given by the user in the User-Input file.
     * 
     * 
     * @return isVerified - ture iff the verfication succeeded and is correct
     * @throws Exception
     */
    private boolean verifyEncryptedFile() throws Exception {
        Certificate certificateA = keyStore.getCertificate(userInput.getCertificateAliasA());
        PublicKey publickeyA = certificateA.getPublicKey();
        Signature signature = signatureProvider.equals("") ?
            Signature.getInstance(signatureAlg) :
                Signature.getInstance(signatureAlg, signatureProvider);
        boolean isVerified;

        signature.initVerify(publickeyA);
        try (FileInputStream fis = new FileInputStream(userInput.getInputCiphertextFilePath())) {
            byte[] ciphertextBytes = fis.readAllBytes();
            byte[] digitalSignatureBytes = Base64.getDecoder().decode(this.properties.getProperty("digitalSignature"));

            signature.update(ciphertextBytes);
            isVerified = signature.verify(digitalSignatureBytes);
            if (!isVerified) {
                System.out.println("Error - verifiction failed");
                try (FileOutputStream fos = new FileOutputStream(userInput.getOutputDecryptedFilePath())) {
                    fos.write("Error - verification failed".getBytes());
                } catch (Exception exception) {
                    throw exception;
                }
            } else {
                System.out.println("Verification succeeded");
            }
        } catch (Exception exception) {
            throw exception;
        }

        return isVerified;
    }

    /**
     * Decrypts the encrypted symmetric key which was generated, encrypted and saved to the configuratino file
     * by Side A during the encryption process.
     * Side A encrypted the symmetric key with an asymmetric encryption algorithm with the user's (side B)
     * public key. Thus, we extract the user's matching private key from the keystore, using its alias
     * given by the user in the User-Input file, and its password given in the command line.
     * 
     * We set the Cipher engine class instance to work with the asymmetric encryption algoithm specified
     * in the configuration file (generated by the Encryptor Program) and with a provider (if suplied by the user)
     * in the mthod changeCipher().
     * 
     * We init the Cipher instance to DECRYPT_MODE with the the user's private key (mentioned above).
     * Then we change the Cipher instance to work with the symmetric encription algorithm specified in the configuration
     * file (generated by the Encryptor Program) and with a provider (if suplied by the user) in the mthod changeCipher()
     * in order to cerate an instance of the engine class SecretKey, which will hold the symmetric key for
     * the symmetric algorithm mentioned above.
     * 
     * @return symmetricKey - the symmetric key for symmetric decryption algorithm, of type SecretKey
     * @throws Exception
     */
    private SecretKey decryptAsymmetricallyKey() throws Exception {
        PrivateKey privateKeyB = (PrivateKey) keyStore.getKey(userInput.getPrivateKeyAliasB(), passwordPrivateKey);
        changeCipher(asymmetricEncryptionAlgForKey, asymmetricEncryptionProviderForKey);
        byte[] encryptedSymmetricKeyBytes = Base64.getDecoder().decode(this.properties.getProperty("encryptedSymmetricKey"));
        cipher.init(Cipher.DECRYPT_MODE, privateKeyB);
        byte[] symmetricKeyBytes = cipher.doFinal(encryptedSymmetricKeyBytes);
        changeCipher(symmetricEncryptionAlg, symmetricEncryptionProvider);
        SecretKey symmetricKey = new SecretKeySpec(symmetricKeyBytes, cipher.getParameters().getAlgorithm()); 
        return symmetricKey;
    }

    /**
     * Decrypts hybridly the encrypted file.
     * First - we get the symmetric key generated by the Encryptor Program in the method decryptAsymmetricallyKey()
     * Then - we instantiate the Cipher engine class instance to work with the symmetric algorithm
     * specified in the configuration file (with a suplied provider / default provider) in the method changeCihper().
     * 
     * Then we load the needed AlgorithmParameters by the method loadAlgParamsFromConfigFile(),
     * and init the Cipher instance to DECRYPT_MODE, with the symmetric key and algorithm-parameters.
     * 
     * Using CipherInputStream, composed with the FileInpuStream for the ciphertext file (path given by the user
     * in User-Input file) and the Cipher instance from above, it decrypts the cipher text while reading it to the 
     * memory. Then we write it to the output file, with the path given by the user in the User-Input file.
     * 
     * @throws Exception
     */
    private void decryptHybridlyFile() throws Exception {
        SecretKey symmetricKey = decryptAsymmetricallyKey();
        changeCipher(symmetricEncryptionAlg, symmetricEncryptionProvider);
        loadAlgParamsFromConfigFile(cipher.getParameters().getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, symmetricKey, algParameters);
        
        try (FileInputStream fis = new FileInputStream(userInput.getInputCiphertextFilePath());
            CipherInputStream cis = new CipherInputStream(fis, cipher);
            FileOutputStream fos = new FileOutputStream(userInput.getOutputDecryptedFilePath())) {
            fos.write(cis.readAllBytes());
            System.out.println("Decryption succeeded");
        } catch (Exception exception) {
            throw exception;
        }
    }

    /**
     * Instantiate the Cipher engine class instance with the given algorithm name in parameter algName
     * If a provider is specified in parameter algProvider, it uses it.
     * Otherwise - it's an empty string - and it uses the default provider
     * 
     * @param algName - the name of the algorithm name
     * @param algProvider - the name of the provider for the algorithm (or empty string for default provider)
     * @throws Exception
     */
    private void changeCipher(String algName, String algProvider) throws Exception{
        cipher = algProvider.equals("") ?
            Cipher.getInstance(algName) :
                Cipher.getInstance(algName, algProvider);
    }
}