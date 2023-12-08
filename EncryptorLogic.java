import java.security.*;
import java.security.cert.Certificate;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.util.Base64;
import java.util.Properties;

public class EncryptorLogic {
    private final String ENCRYPTED_SYMMETRIC_KEY_ALIAS_CONFIG = "encryptedSymmetricKey";
    private final String SYMMETRIC_ALG_PARAMETERS_ALIAS_CONFIG = "algParameters";
    private final String DIGITIAL_SIGNATURE_ALIAS_CONFIG = "digitalSignature";
    private final boolean appendFlag = true;
    private Properties properties = new Properties();
    private String symmetricEncryptionAlg;
    private String symmetricEncryptionProvider;
    private int symmertricKeySize;
    private boolean flagDefaultIv = true;
    private String secureRandomAlg; 
    private String secureRandomProvider;
    private int ivBytesLength;
    private String signatureAlg;
    private String signatureProvider;
    private String asymmetricEncryptionAlgForKey;
    private String asymmetricEncriptionProvdierForKey;    
    private EncryptorUserInput userInput;
    private KeyStore keyStore;
    private Cipher cipher;
    private char[] passwordKeyStore;
    private char[] passwordPrivateKey;

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
    public EncryptorLogic(char[] passwordKeyStore, char[] passwordPrivateKey, String userInputFilePath) {
        this.passwordKeyStore = passwordKeyStore;
        this.passwordPrivateKey = passwordPrivateKey;
        userInput = new EncryptorUserInput(userInputFilePath);
    }

    /**
     * The public API this class exposes to this class' client:
     * Encrypts hybridly a file:
     *   symmetricaly the file to a given path
     *   and assymetrically the symmetric key to the output configuration file in a given path
     * Signs the ENCRYPTED file (as the best practice requires) by an "assymetric" digital signature
     * with all the parameters given by the user in the User-Input file and the configuration file
     * (mentioned in the User-Input file) and saves the signature in the output configuration file.
     *
     * @throws Exception
     */
    public void encryptAndSign() throws Exception {
        userInput.init();
        loadConfigFromFile();
        loadKeyStore();
        encryptHibridlyFile();
        signEncryptedFile();
    }

    /**
     * Loads the properties the user chose in the configuration file
     * 
     * @throws Exception
     */
    private void loadConfigFromFile() throws Exception {
        try (FileInputStream fis = new FileInputStream(userInput.getInputConfigFilePath())) {
            this.properties.load(fis);
            this.symmetricEncryptionAlg = this.properties.getProperty("symmetricEncryptionAlg");
            this.symmetricEncryptionProvider = this.properties.getProperty("symmetricEncryptionProvider", "");
            this.symmertricKeySize = Integer.parseInt(this.properties.getProperty("symmetricKeySize"));
            this.flagDefaultIv = Boolean.parseBoolean(this.properties.getProperty("flagDefaultIv", "true"));
            this.secureRandomAlg = this.properties.getProperty("secureRandomAlg");
            this.secureRandomProvider = this.properties.getProperty("secureRandomProvider", "");
            this.ivBytesLength = Integer.parseInt(this.properties.getProperty("ivBytesLength"));
            this.signatureAlg = this.properties.getProperty("signatureAlg");
            this.signatureProvider = this.properties.getProperty("signatureProvider", "");
            this.asymmetricEncryptionAlgForKey = this.properties.getProperty("asymmetricEncryptionAlgForKey");
            this.asymmetricEncriptionProvdierForKey = this.properties.getProperty("asymmetricEncriptionProviderForKey", "");
        } catch (Exception exception) {
            throw exception;
        }
    }

    /**
     * Loads the keystore located in the path given by the user in the User-Input file
     * with its password given by the user in the command line.
     * 
     * We used the KeyStore engine class which can load a keystore from the storage.
     * the KsyStore instance is created with its type, given by the user in the User-Input file.
     * If a provider was suplied by the user in the User-Input file as well, so it's loaded 
     * with this provider. Otherwise by the system's default.
     * 
     * @throws Exception
     */
    private void loadKeyStore() throws Exception {
        try (FileInputStream fis = new FileInputStream(userInput.getKeyStorePathA())) {
            keyStore = userInput.getKeyStoreProvider().equals("") ?
                KeyStore.getInstance(userInput.getKeyStoreType()) :
                    KeyStore.getInstance(userInput.getKeyStoreType(), userInput.getKeyStoreProvider());
            keyStore.load(fis, passwordKeyStore);
        } catch (Exception exception) {
            throw exception;
        }
    }

    /**
     * Generates an IV by pseudo-random-number generated by the SecureRandom engine class
     * 
     * Using SecureRandom ensures us that the generated pseudo-random-number (PRNG) is strong
     * and secure for cryptographic needs.
     * 
     * We initialize it with the secure-random-aglorithm given by the user in the configuration file.
     * Also, if a provider was specified as well, it's used too.
     * Otherwise - it's instantiated with the default provider.
     * 
     * The length of the number (in Bytes) is determined by ivBytesLength property
     * given by the user in the configuration file.
     * 
     * We DO NOT set seed so it will indeed be a pseudo random
     * 
     * @return iv - for the symmetric encryption of the file, of type IvParameterSpec
     * @throws Exception
     */
    private IvParameterSpec generateIv() throws Exception {
        SecureRandom secureRandom = secureRandomProvider.equals("") ?
            SecureRandom.getInstance(secureRandomAlg) :
                SecureRandom.getInstance(secureRandomAlg, secureRandomProvider);
        byte[] ivBytes = new byte[ivBytesLength];
        
        secureRandom.nextBytes(ivBytes);
        
        return new IvParameterSpec(ivBytes);
    }

    /**
     * Encrypts hibridly the plaintext in the file in the path given by the user in the User-Input file.
     * 
     * We first use the Cipher engine class which will encrypt the file.
     * We get its instance with the encryption algorithm provided by the user in the configuration file.
     * Also - if an algorithm provider is specified then it uses it, Otherwise - it uses the default.
     * (This occurs in changeCipher() method).
     * 
     * We generate a symmetric key using the class engine SecretKey in the method generateSymmetricKey().
     * We use the flag flagDefaultIv specified by the user in the configuration file to determine
     * whether to generate an IV by parameters provided by the user, or let the Cipher engine class
     * create a default IV (if needed).
     * 
     * Then we init the Cipher instance to ENCRYPT_MODE with the generated symmetric key (and the IV, if was generated)
     * 
     * We Use CipherInputStream which is composed by the FileInputStream represents the plaintext file,
     * and the Cipher instance above, s.t. when the data is read to the memory, it encrypts it.
     * Then, we write the ciphertext to the output file in the path given by the user in the User-Input file.
     * 
     * After, we save the AlgorithmParameters to the output configuration file for the Decryptor program.
     * To make this encryption hibrid, we encrypt asymmetrically the symmetric key in the method encryptAsymmetricallyKey().
     * 
     * @throws Exception
     */
    private void encryptHibridlyFile() throws Exception {
        try (FileInputStream fis = new FileInputStream(userInput.getInputPlaintextFilePath());
            FileOutputStream fos = new FileOutputStream(userInput.getOutputCipherFilePath(), !appendFlag)) {
            changeCipher(symmetricEncryptionAlg, symmetricEncryptionProvider);
            SecretKey symmetricKey = generateSymmetricKey(cipher.getParameters().getAlgorithm());
            if (flagDefaultIv) {
                cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            } else {
                IvParameterSpec iv = generateIv();
                cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, iv);
            }
            
            try (CipherInputStream cis = new CipherInputStream(fis, cipher)) {
                // ENCRYPT TO FILE
                fos.write(cis.readAllBytes());
                // END ENCRYPT TO FILE
            }
    
            byte[] encodedAlgParametersBytes = cipher.getParameters().getEncoded();
            storeToConfigFile(SYMMETRIC_ALG_PARAMETERS_ALIAS_CONFIG, encodedAlgParametersBytes);
            encryptAsymmetricallyKey(symmetricKey);
            System.out.println("File has been encrypted successfully!");
        } catch (Exception exception) {
            throw exception;
        }
    }

    /**
     * Generates the symmetric key for the given symmetric encryption algorithm
     * 
     * We get as an input the algorithm name for creating the key
     * We use the KeyGenerator engine class in order to generate the key
     * We instantiate the KeyGenerator instance with the givan algorithm name,
     * and with the provider (if one was specified in the configuration files, otherwise it uses the default).
     * We also let the user choose the size of the key, by specifing it in the configuration file.
     * Finally, we use the method generateKey() of the keyGenerator to genegerate the symmetric key.
     * 
     * @param algName - the name of the symmetric encryption algorithm for which the key will be generated
     * @return symmetricKey - the generated symmetric key, of type SecretKey
     * @throws Exception
     */
    private SecretKey generateSymmetricKey(String algName) throws Exception {
        KeyGenerator keyGenerator = symmetricEncryptionProvider.equals("") ?
            KeyGenerator.getInstance(algName) :
                KeyGenerator.getInstance(algName, symmetricEncryptionProvider);
        keyGenerator.init(symmertricKeySize);
        SecretKey symmetricKey = keyGenerator.generateKey();
        
        return symmetricKey;
    }

    /**
     * Encrypts the given symmetric key by assymetric encryption, and saves it
     * to the output configuration file for future use of the Decryptor program
     * 
     * We load the certificate of the reciver (side B) from the user's keystore
     * by its alias given by the user in User-Input file, using the Certificate engine class
     * 
     * We change the cipher instance settings for assymetric encryption, by the method changeCipher()
     * and init it to ENCRYPT_MODE, using the public key of side B which is in his/her certificate we excracted above
     * 
     * We encrypt it in one line with the method doFinal() and save it to the output configuration file
     * 
     * @param symmetricKey - the symmetric key to be assymetrically encrypted.
     * @throws Exception
     */
    private void encryptAsymmetricallyKey(SecretKey symmetricKey) throws Exception {
        Certificate certificateB = keyStore.getCertificate(userInput.getCertificateAliasB());

        changeCipher(asymmetricEncryptionAlgForKey, asymmetricEncriptionProvdierForKey);
        cipher.init(Cipher.ENCRYPT_MODE, certificateB);
        byte[] encryptedKeyBytes = cipher.doFinal(symmetricKey.getEncoded());
        storeToConfigFile(ENCRYPTED_SYMMETRIC_KEY_ALIAS_CONFIG, encryptedKeyBytes); // Stores the encripted key
    }
    
    /**
     * Stores a given array of bytes to the output configuration file
     * as an entry associated with the given alias.
     * We decode the bytes to Base64 so the user will be able to send the configuration file
     * throw the web (pure bytes are sometimes ignored to be sent by internet protocols)
     * 
     * @param alias - the wanted alias of the entry
     * @pararm value - the bytes representing the value of the entry to be stored
     * @throws exception
    */
    private void storeToConfigFile(String alias, byte[] value) throws Exception {
        String valueString = Base64.getEncoder().encodeToString(value);
        File outputConfigFile = new File(userInput.getOutputConfigFilePath());
        outputConfigFile.createNewFile();
        
        try (FileOutputStream fos = new FileOutputStream(outputConfigFile, !appendFlag)) {
            properties.setProperty(alias, valueString);
            properties.store(fos, "");
        } catch (Exception exception) {
            throw exception;
        }
    }

    /**
     * Signs the enctypted file with an "asymmetric" digital signature algorithm with the user's privte key
     * 
     * We extract the user's private key from the keystore, with its alias given by the user in the User-Input file
     * and its password given by the user in the command line input.
     * We asgin it to an instance of the appropriate engine class PrivateKey.
     * 
     * We create a Signature engine class instance for the "assymetric" digital signature
     * with the signature algorithm specified by the user in the configuration file,
     * and the algorithm provider if one was specified by the user in the configuration file
     * (otherwise - uses the default provider)
     * 
     * We read the cipher text from the storage and sign it with the private key of the user 
     * and we store this digital signature to the output configuratino file
     *
     * @throws Exception
     */
    private void signEncryptedFile() throws Exception {
        PrivateKey privateKeyA = (PrivateKey)keyStore.getKey(userInput.getPrivateKeyAliasA(), passwordPrivateKey);
        Signature signature = signatureAlg.equals("") ?
            Signature.getInstance(signatureAlg) :
                Signature.getInstance(signatureAlg, signatureProvider);
        try (FileInputStream fis = new FileInputStream(userInput.getOutputCipherFilePath())) {
            byte[] encryptedData = fis.readAllBytes();
            signature.initSign(privateKeyA);
            signature.update(encryptedData);
            byte[] signedFile = signature.sign();
            storeToConfigFile(DIGITIAL_SIGNATURE_ALIAS_CONFIG, signedFile);
            System.out.println("File has been signed successfully!");
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
    private void changeCipher(String algName, String algProvider) throws Exception {
        cipher = algProvider.equals("") ?
            Cipher.getInstance(algName) :
                Cipher.getInstance(algName, algProvider);
    }
}