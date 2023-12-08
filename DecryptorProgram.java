public class DecryptorProgram {

    /**
     * The entry point for the Decryptor program
     * 
     * Receives 3 inputs from the user through the command line in this order:
     * 1. the password for the keystore
     * 2. the password for the private key
     * 3. the path to the User-Input parameter file
     * 
     * Calls the DecryptorLogic's method that verifies the digital signature and decrypts hybridly
     * the wanted file, specified in the User-Input file.
     * 
     * If one of the user inputs doesn't math the decryption logic, an exception will be thrown
     * and displayed to the user.
     * 
     * @param args - as described above
     */
    public static void main(String[] args) {
        char[] passwordKeyStore = args[0].toCharArray();
        char[] passwordPrivateKey = args[1].toCharArray();
        String userInputParametersFilePath = args[2];
        DecryptorLogic decryptorLogic = new DecryptorLogic(passwordKeyStore, passwordPrivateKey, userInputParametersFilePath);

        try {
            decryptorLogic.verifyAndDecrypt();
        } catch (Exception exception) {
            System.out.println(exception.getMessage());
        }
    }
}
