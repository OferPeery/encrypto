import java.util.Properties;
import java.io.*;

public class EncryptorUserInput {
    private Properties properties = new Properties();
    private String path;
    private String keyStorePathA;
    private String inputConfigFilePath;
    private String inputPlaintextFilePath;
    private String keyStoreType;
    private String keyStoreProvider;
    private String privateKeyAliasA;
    private String certificateAliasB;
    private String outputCipherFilePath;
    private String outputConfigFilePath;
    
    /**
     * Constructs a new EncryptorUserInput object represents the user input properties
     * the user chose in the User-Input file in the given path
     * 
     * @param usetInputFilepath
     */
    public EncryptorUserInput(String usetInputFilepath) {
        this.path = usetInputFilepath;
    }

    /**
     * Loads all the user inpnuts that are in the User-Input file
     * 
     * @throws Exception
     */
    public void init() throws Exception {
        this.properties.load(new FileInputStream(path));
        this.keyStorePathA = this.properties.getProperty("keyStorePathA");
        this.inputConfigFilePath = properties.getProperty("inputConfigFilePath");
        this.inputPlaintextFilePath = properties.getProperty("inputPlaintextFilePath");
        this.keyStoreType = properties.getProperty("keyStoreType");
        this.keyStoreProvider = properties.getProperty("keyStoreProvider");
        this.privateKeyAliasA = properties.getProperty("privateKeyAliasA");
        this.certificateAliasB = properties.getProperty("certificateAliasB");
        this.outputCipherFilePath = properties.getProperty("outputCipherFilePath");
        this.outputConfigFilePath = properties.getProperty("outputConfigFilePath");
    }


    // Get methods for the properties loaded from the file

    public String getKeyStorePathA() {
        return this.keyStorePathA;
    }

    public String getInputConfigFilePath() {
        return this.inputConfigFilePath;
    }

    public String getInputPlaintextFilePath() {
        return this.inputPlaintextFilePath;
    }

    public String getKeyStoreType() {
        return this.keyStoreType;
    }

    public String getKeyStoreProvider() {
        return this.keyStoreProvider;
    }

    public String getPrivateKeyAliasA() {
        return this.privateKeyAliasA;
    }

    public String getCertificateAliasB() {
        return this.certificateAliasB;
    }

    public String getOutputCipherFilePath() {
        return this.outputCipherFilePath;
    }

    public String getOutputConfigFilePath() {
        return this.outputConfigFilePath;
    }
}
