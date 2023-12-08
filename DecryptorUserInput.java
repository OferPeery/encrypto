import java.io.FileInputStream;
import java.util.Properties;

public class DecryptorUserInput {
    private Properties properties = new Properties();
    private String path;
    private String keyStorePathB;
    private String inputConfigFilePath;
    private String inputCiphertextFilePath;
    private String keyStoreType;
    private String keyStoreProvider;
    private String privateKeyAliasB;
    private String certificateAliasA;
    private String outputDecryptedFilePath;

    /**
     * Constructs a new DencryptorUserInput object represents the user input properties
     * the user chose in the User-Input file in the given path
     * 
     * @param usetInputFilepath
     */
    public DecryptorUserInput(String usetInputFilepath){
        this.path = usetInputFilepath;
    }

    /**
     * Loads all the user inputs that are in the User-Input file
     * 
     * @throws Exception
     */
    public void init() throws Exception {
        this.properties.load(new FileInputStream(path));
        this.keyStorePathB = this.properties.getProperty("keyStorePathB");
        this.inputConfigFilePath = properties.getProperty("inputConfigFilePath");
        this.inputCiphertextFilePath = properties.getProperty("inputCiphertextFilePath");
        this.keyStoreType = properties.getProperty("keyStoreType");
        this.keyStoreProvider = properties.getProperty("keyStoreProvider");
        this.privateKeyAliasB = properties.getProperty("privateKeyAliasB");
        this.certificateAliasA = properties.getProperty("certificateAliasA");
        this.outputDecryptedFilePath = properties.getProperty("outputDecryptedFilePath");
    }

    // Get methods for the properties loaded from the file

    public String getKeyStorePathB() {
        return this.keyStorePathB;
    }

    public String getInputConfigFilePath() {
        return this.inputConfigFilePath;
    }

    public String getInputCiphertextFilePath() {
        return this.inputCiphertextFilePath;
    }

    public String getKeyStoreType() {
        return this.keyStoreType;
    }

    public String getKeyStoreProvider() {
        return this.keyStoreProvider;
    }

    public String getPrivateKeyAliasB() {
        return this.privateKeyAliasB;
    }

    public String getCertificateAliasA() {
        return this.certificateAliasA;
    }

    public String getOutputDecryptedFilePath() {
        return this.outputDecryptedFilePath;
    }
}
