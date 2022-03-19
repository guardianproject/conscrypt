package com.example.conscrypt_transportauthclient;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyStore;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.conscrypt.Conscrypt;
import org.conscrypt.OpenSSLContextImpl;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.security.Provider.Service;
import java.util.Arrays;
import javax.net.ssl.X509TrustManager;
import java.util.Properties;
public class HTTPSClient {

    private int port = 8333;
    private  OpenSSLContextImpl sslContextConscrypt;
    private static Provider p;
    public static String authMechanisum;
    public static String clientName="John James";
    public static String [] ExporterLabelArray={"EXPORTER-HTTP-Transport-Authentication-Signature","EXPORTER-HTTP-Transport-Authentication-HMAC"};
    public static int labellength=32;
    public static KeyStore clientkeyStore;
    private static String clientPrivateKey ="";
    private static String serverKeystore="";
    private static String clientKeystore="";
    private static String serverPassword="";
    private static String clientPassword="";
    private static String serverHost = "";
    private static Properties prop = new Properties();

    public static void loadConfig(String configFilePath) throws IOException {


        //load config.properties file which conatain the keystore for client and server, also their respective passwords
        String propFileName = "config.properties";
        InputStream  configFile = HTTPSClient.class.getClassLoader().getResourceAsStream(propFileName);
        File configDir = null;
        if (configFile == null) {
            System.out.println("Loading config from " + configFilePath);
            configFile = new FileInputStream(configFilePath);
            configDir = new File(configFilePath).getParentFile();
        }
        if (configFile != null) {
            prop.load(configFile);
        } else {
            throw new FileNotFoundException("property file '" + configFile + "' not found in the classpath");
        }

        //Save the values in Local variables
        serverKeystore=prop.getProperty("SERVERKEYSTORE");
        clientKeystore=prop.getProperty("CLIENTKEYSTORE");
        serverPassword=prop.getProperty("SERVERKEYSTOREPASSWORD");
        clientPassword=prop.getProperty("CLIENTKEYSTOREPASSWORD");
        clientPrivateKey=prop.getProperty("CLIENTPRIVATEKEY");
        serverHost = prop.getProperty("SERVERHOST", "127.0.0.1");

        if (configDir != null) {
            System.out.println("Using keystores from config dir " + configDir);
            serverKeystore = new File(configDir, serverKeystore).getAbsolutePath();
            clientKeystore = new File(configDir, clientKeystore).getAbsolutePath();
            clientPrivateKey = new File(configDir, clientPrivateKey).getAbsolutePath();
        }
    }

    public static void main(String[] args) throws IOException {

        // First argument should be HMAC or Signature which will define the which algorithum to use.
        //ave user input in authMechanisum
        if(args.length<=0){
            System.out.println(" Usage error: Please specify the mechnisum");
            return;
        }
	if (args[0].equals("HMAC")) {
	    authMechanisum=args[0];
	} else if(args[0].equals("Signature")) {
	    authMechanisum=args[0];
	} else {
	    System.out.println(" Usage error: Please specify the mechnisum");
	    return;
	}

        if (args != null && args.length > 1) {
            loadConfig(args[1]);
        } else {
            loadConfig(null);
        }

        //Start the Client in new thread
        HTTPSClient client = new HTTPSClient();
        client.run();
    }

    //constructor
    HTTPSClient(){
    }

    // Create the and initialize the SSLContext
    private void InitConscrypt() throws GeneralSecurityException, IOException {
        //Initialize the Cponscrypt as Providr and build its Instance
        this.p = Conscrypt.newProviderBuilder()
                .setName("Conscryptprovider")
                .provideTrustManager(false)
                .defaultTlsProtocol("TLSv1.2").build();
        //set conscrypt as default java security provider
        Security.insertProviderAt(p, 1);
        //p.getService(type, algorithm)
    }

    // Create OpenSSLContext for Conscrypt Socket
    private OpenSSLContextImpl createSSLContextConscrypt(){
        try{
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            File clientKeystorefile = new File(clientKeystore);
            URL ServerFileURL=HTTPSClient.class.getClassLoader().getResource(clientKeystore);
            if (!clientKeystorefile.canRead()) {
                if (ServerFileURL == null) {
                    throw new IllegalArgumentException("file not found! " + clientKeystore);
                }
                clientKeystorefile = new File(ServerFileURL.toURI());
            }

            System.out.println("clientKeystorefile="+clientKeystorefile.getAbsolutePath());
            keyStore.load(new FileInputStream(clientKeystorefile.getAbsolutePath()),clientPassword.toCharArray());
            KeyStore trustStore = KeyStore.getInstance("PKCS12");


            //Server public key store in truststore
            File serverKeystorefile = new File(serverKeystore);
            if (!serverKeystorefile.canRead()) {
                try {
                    URL ClientFileURL = new HTTPSClient().getClass().getClassLoader().getResource(serverKeystore);
                    if (ClientFileURL == null) {
                        throw new IllegalArgumentException("file not found! " + serverKeystore);
                    }
                    serverKeystorefile = new File(ClientFileURL.toURI());
                } catch (URISyntaxException e) {
                    serverKeystorefile = new File(HTTPSClient.class.getClassLoader().getResource(serverKeystore).getPath());
                }
            }
            System.out.println("serverKeystorefile="+serverKeystorefile.getAbsolutePath());
            trustStore.load(new FileInputStream(serverKeystorefile.getAbsolutePath()),serverPassword.toCharArray());
            clientkeyStore=trustStore;
            //keyStore.load(new FileInputStream("server-certificate.p12"),"".toCharArray());
            // Create key manager
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
            keyManagerFactory.init(keyStore, clientPassword.toCharArray());
            KeyManager[] km = keyManagerFactory.getKeyManagers();

            // Create trust manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
            trustManagerFactory.init(trustStore);
            TrustManager[] tm = trustManagerFactory.getTrustManagers();


            // Trust All certificate
            // Conscrypt Engine keep raising exception got UnVerified Peer so decided to confure it to trust all CA
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers()
                        {
                            return null;
                        }
                        public void checkClientTrusted(
                                java.security.cert.X509Certificate[] certs,
                                String authType )
                        {
                        }
                        public void checkServerTrusted(
                                java.security.cert.X509Certificate[] certs,
                                String authType )
                        {
                        }
                    }
            };

            // Create openssl context and Initialize the Conscrypt Engine and
            sslContextConscrypt = (OpenSSLContextImpl) Conscrypt.newPreferredSSLContextSpi();
            sslContextConscrypt.engineInit(km,  trustAllCerts, null);
            return sslContextConscrypt;
        } catch (Exception ex){
            ex.printStackTrace();
        }

        return null;
    }


    // Start the client
    public void run(){
        try{


            InitConscrypt();
            this.createSSLContextConscrypt();

            // Get sslsocket factory instance
            SSLSocketFactory sslSocketFactory=sslContextConscrypt.engineGetSocketFactory();

            // Create conscrypt based client socket
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(this.serverHost, this.port);
            System.out.println("SSL client started");

            //pass socket handling to new class (Thread)
            new ClientThread(sslSocket).start();
        } catch (Exception ex){
            ex.printStackTrace();
        }
    }

    // Thread handling the socket to server
    static class ClientThread extends Thread implements HandshakeCompletedListener {
        private static byte [] ekm;


        // Hanshake comlete listner
        public void handshakeCompleted(HandshakeCompletedEvent vente) {
            try {
                SSLSocket sslSocket=vente.getSocket();
                System.out.println("handshake completed successfully");
                byte [] b=null;
                if(authMechanisum.equals("HMAC")){
                    if(ExporterLabelArray.length>1 && !ExporterLabelArray[0].equals("") ){

                        // Export Keying material from JNI wrapper
                        // both possible lable values are stored in String array and referred
                        this.ekm=Conscrypt.exportKeyingMaterial(sslSocket, ExporterLabelArray[0],b , labellength);
                    }
                }
                else if(authMechanisum.equals("Signature")){
                    if(ExporterLabelArray.length>1 && !ExporterLabelArray[1].equals("") ){

                        // Export Keying material from JNI wrapper
                        this.ekm=Conscrypt.exportKeyingMaterial(sslSocket, ExporterLabelArray[1],b , labellength);
                    }
                }
                else{
                    System.out.println("Invalid selection of Signature Algorithum");

                }
                System.out.println("EKM="+this.bytesToHex(this.ekm));
            }
            catch(Exception e) {
                System.out.println("Error in handshake ");
                e.printStackTrace();
            }
        }

        private SSLSocket sslSocket = null;
        String InputUserID = "john.doe";
        ClientThread(SSLSocket sslSocket){
            this.sslSocket = sslSocket;
        }

        // Sign asymmetric algorithum SHA256WithRSA
        private static String signSHA256RSA(String input, String strPk) throws Exception {
            String realPK = strPk.replaceAll("-----END PRIVATE KEY-----", "").replaceAll("-----BEGIN PRIVATE KEY-----", "").replaceAll("\n", "");
            byte[] b1 = Base64.getDecoder().decode(realPK);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(b1);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(kf.generatePrivate(spec));
            privateSignature.update(input.getBytes("UTF-8"));
            byte[] s = privateSignature.sign();
            return Base64.getEncoder().encodeToString(s);
        }

        // Convert String to byte Array
        public static byte[] asBytes (String s) {
            String tmp;
            byte[] b = new byte[s.length() / 2];
            int i;
            for (i = 0; i < s.length() / 2; i++) {
                tmp = s.substring(i * 2, i * 2 + 2);
                b[i] = (byte)(Integer.parseInt(tmp, 16) & 0xff);
            }
            return b;                                            //return bytes
        }

        // HMAC with SHA256
        static public byte[] calcHmacSha512(byte[] secretKey, byte[] message) {
            byte[] hmacSha256 = null;
            try {
                Mac mac = Mac.getInstance("HmacSHA512");
                SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA512");
                mac.init(secretKeySpec);
                hmacSha256 = mac.doFinal(message);
            } catch (Exception e) {
                throw new RuntimeException("Failed to calculate hmac-sha512", e);
            }
            return hmacSha256;
        }
        private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);


        // Get IOD for Symmetric Digest Algorithum
        private String getOIDDigestAlgorithum(String digestAlgorithmName) {
            String oid = null;
            //String MacAlgorithmName = "HmacSHA512";
            //Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
            Service service = p.getService("MessageDigest", digestAlgorithmName);
            if (service != null) {
                String string = service.toString();
                String array[] = string.split("\n");
                if (array.length > 1) {
                    string = array[array.length - 1];
                    array = string.split("[\\[\\]]");
                    if (array.length > 2) {
                        string = array[array.length - 2];
                        array = string.split(", ");
                        Arrays.sort(array);
                        oid=array[0];
                        return oid;
                    }
                }
            }
            return null;

        }


        // Get IOD for ASymmetric  Algorithum
        private static String getOIDMacAlgorithum(String MacAlgorithmName) {
            String oid = null;
            Service service = p.getService("Mac", MacAlgorithmName);
            if (service != null) {
                String string = service.toString();
                //System.out.println("service ="+service);
                String array[] = string.split("\n");
                if (array.length > 1) {
                    string = array[array.length - 2];
                    array = string.split("[\\[\\]]");
                    //System.out.println("service.aliases ="+string);
                    if (array.length > 2) {
                        string = array[array.length - 2];
                        array = string.split(", ");
                        Arrays.sort(array);
                        for (int i=0;i<array.length;i++) {
                            //System.out.println("oid ="+array[i]);
                        }
                        oid = array[0];
                        //System.out.println("oid ="+oid);
                        return oid;
                    }
                }
            }
            return null;
        }

        //bytesToHex
        public static String bytesToHex(byte[] bytes) {
            byte[] hexChars = new byte[bytes.length * 2];
            for (int j = 0; j < bytes.length; j++) {
                int v = bytes[j] & 0xFF;
                hexChars[j * 2] = HEX_ARRAY[v >>> 4];
                hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
            }
            return new String(hexChars, StandardCharsets.UTF_8);
        }

        // Read private key
        private static String getKey(String filename) throws IOException {
            // Read key from file
            String strKeyPEM = "";
            BufferedReader br = new BufferedReader(new FileReader(filename));
            String line;
            while ((line = br.readLine()) != null) {
                strKeyPEM += line + "\n";
            }
            br.close();
            return strKeyPEM;
        }
        public static String getPrivateKey(String filename) throws IOException, GeneralSecurityException {
            String privateKeyPEM = getKey(filename);
            return privateKeyPEM;
        }

        public void run(){
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());
            try{
                // Start handshake
                this.sslSocket.addHandshakeCompletedListener(this);
                this.sslSocket.startHandshake();

                // Get session after the connection is established
                SSLSession sslSession = sslSocket.getSession();

                //System.out.println("Client SSLSession :");
                //System.out.println("\tProtocol : "+sslSession.getProtocol());
                //System.out.println("\tCipher suite : "+sslSession.getCipherSuite());

                // Start handling application content
                InputStream inputStream = sslSocket.getInputStream();
                OutputStream outputStream = sslSocket.getOutputStream();

                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));

                try {
                    OutputStream rawOut = sslSocket.getOutputStream();
                    PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(rawOut)));
                    try {
                        // get path to class file from header
                        BufferedReader in =new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));

                        //
                        String OIDofgetOIDMacAlgorithum="";
                        String SignatureParamP="";
                        String SignatureParamU = Base64.getEncoder().encodeToString(this.InputUserID.getBytes());
                        String SignatureParamA="";
                        if (authMechanisum.equals("HMAC")) {
                            SignatureParamA=getOIDMacAlgorithum("HmacSHA512");
                            System.out.println("Export_Keying_Material: "+bytesToHex(this.ekm));


                            try {
                                byte[] hmacSha256 = calcHmacSha512(bytesToHex(this.ekm).toString().getBytes("UTF-8"), this.InputUserID.getBytes("UTF-8"));
                                SignatureParamP=bytesToHex(hmacSha256);
                                System.out.println(String.format("Hex: %032x", new BigInteger(1, hmacSha256)));
                                out.print("CONNECT guardianproject.info:443 HTTP/1.0\r\n");
                                out.print("Content-Length: 0\r\n");
                                out.print("Transport-Authentication: HMAC u="+SignatureParamU
                                        +";a="+SignatureParamA
                                        +";p="+SignatureParamP
                                        +"\r\n");

                                out.flush();


                                String line = null;
                                while((line = bufferedReader.readLine()) != null){
                                    System.out.println("Client Received : "+line);

                                    if(line.trim().startsWith("HTTP/1.0 200")){
					System.out.println("Got 200, done!");
                                        break;
                                    }
                                }
                            } catch (IOException ie) {
                                ie.printStackTrace();
                                return;
                            }
                        } else if(authMechanisum.equals("Signature")) {
                            SignatureParamA=getOIDDigestAlgorithum("SHA256withRSA");

                            String key = getPrivateKey(clientPrivateKey);
                            System.out.println("KeyStoreSig loaded successfully="+key.toString());
                            String base64Signature = signSHA256RSA(clientName,key);
                            //System.out.println("Signature="+base64Signature);
                            out.println("HTTP/1.0 400 " + "\r\n");
                            out.println("Content-Type: text/html\r\n\r\n");
                            out.flush();
                            System.out.println("Client dont support Signature yet!  ");
                        }
                        else{
                            System.out.println("Unsuppoted Algorithum!");
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                        // write out error response
                        out.println("HTTP/1.0 400 " + e.getMessage() + "\r\n");
                        out.println("Content-Type: text/html\r\n\r\n");
                        out.flush();
                    }

                } catch (IOException ex) {
                    // eat exception (could log error to log file, but
                    // write out to stdout for now).
                    System.out.println("error writing response: " + ex.getMessage());
                    ex.printStackTrace();

                } finally {
                    try {
                        sslSocket.close();
                    } catch (IOException e) {
                    }
                }

            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }
}