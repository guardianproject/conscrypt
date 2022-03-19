package com.example.conscrypt_transportauth;


import org.conscrypt.Conscrypt;
import org.conscrypt.OpenSSLContextImpl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Properties;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import static java.nio.charset.StandardCharsets.UTF_8;

public class HTTPSServer  {

    HashMap<String, String> verifiedClient = new HashMap<String, String>();
    public static String [] ExporterLabelArray={"EXPORTER-HTTP-Transport-Authentication-Signature","EXPORTER-HTTP-Transport-Authentication-HMAC"};
    protected static final String TAG = HTTPSServer.class.getName();
    private static String serverKeystore="";
    private static String clientKeystore="";
    private static String serverPassword="";
    private static String clientPassword="";
    private static int EKMlabelLength=0;
    private int port = 8333;
    private boolean isServerDone = false;
    PublicKey a;
    private   OpenSSLContextImpl sslContextConscrypt;
    private static Provider p;
    private static Properties prop = new Properties();
    static {
        try {
            //System.out.println(System.getProperty("java.library.path"));

            //Load BooringSSL JNI Library
            System.loadLibrary("conscrypt_openjdk_jni");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
            System.exit(1);
        }
    }

    //load config.properties file which conatain the keystore for client and server, also their respective passwords
    public static void loadConfig(String configFilePath) throws IOException {

        String propFileName = "config.properties";
        InputStream configFile = HTTPSServer.class.getClassLoader().getResourceAsStream(propFileName);
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
        System.out.println("config dir " + configDir);

        //Save the values in Local variables
        serverKeystore=prop.getProperty("SERVERKEYSTORE");
        clientKeystore=prop.getProperty("CLIENTKEYSTORE");
        serverPassword=prop.getProperty("SERVERKEYSTOREPASSWORD");
        clientPassword=prop.getProperty("CLIENTKEYSTOREPASSWORD");
        EKMlabelLength=Integer.parseInt(prop.getProperty("EKMLABELLENGTH"));

        if (configDir != null) {
            System.out.println("Using keystores from config dir " + configDir);
            serverKeystore = new File(configDir, serverKeystore).getAbsolutePath();
            clientKeystore = new File(configDir, clientKeystore).getAbsolutePath();
        }

        if(EKMlabelLength<32 || serverKeystore.equals("") || clientKeystore.equals("")){
            throw new FileNotFoundException("Invalud file name or lables size");
        }
    }
    public static void main(String[] args) throws IOException {

        if (args != null && args.length > 0) {
            loadConfig(args[0]);
        } else {
            loadConfig(null);
        }
        //Start the Client in new thread
        HTTPSServer server = new HTTPSServer();
        server.run();
    }

    HTTPSServer(){
    }



    HTTPSServer(int port){
        this.port = port;
    }



    // Create the and initialize the SSLContext
    private void InitConscrypt() throws GeneralSecurityException, IOException {
        p = Conscrypt.newProviderBuilder()
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
            System.out.println("Loading server keystore: " + serverKeystore);
            File serverKeystorefile = new File(serverKeystore);
            if (!serverKeystorefile.canRead()) {
                try {
                    URL ServerFileURL = new HTTPSServer().getClass().getClassLoader().getResource(serverKeystore);
                    if (ServerFileURL == null) {
                        throw new IllegalArgumentException("file not found! " + serverKeystore);
                    }
                    serverKeystorefile = new File(ServerFileURL.toURI());
                } catch (URISyntaxException e) {
                    serverKeystorefile = new File(HTTPSServer.class.getClassLoader().getResource(serverKeystore).getPath());
                }
            }
            System.out.println("serverKeystorefile=" + serverKeystorefile.getAbsolutePath());
            keyStore.load(new FileInputStream(serverKeystorefile.getAbsolutePath()), serverPassword.toCharArray());


            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            System.out.println("Loading client keystore: " + clientKeystore);
            File clientKeystorefile = new File(clientKeystore);
            if (!clientKeystorefile.canRead()) {
                try {
                    URL ClientFileURL = new HTTPSServer().getClass().getClassLoader().getResource(clientKeystore);
                    if (ClientFileURL == null) {
                        throw new IllegalArgumentException("file not found! " + clientKeystore);
                    }
                    clientKeystorefile = new File(ClientFileURL.toURI());
                } catch (URISyntaxException e) {
                    clientKeystorefile = new File(HTTPSServer.class.getClassLoader().getResource(clientKeystore).getPath());
                }
            }
            System.out.println("clientKeystorefile=" + clientKeystorefile.getAbsolutePath());
            trustStore.load(new FileInputStream(clientKeystorefile.getAbsolutePath()), clientPassword.toCharArray());

            // Create key manager
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
            keyManagerFactory.init(keyStore, serverPassword.toCharArray());
            KeyManager[] km = keyManagerFactory.getKeyManagers();

            // Create trust manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
            trustManagerFactory.init(trustStore);
            TrustManager[] tm = trustManagerFactory.getTrustManagers();

            // Create openssl context and Initialize the Conscrypt Engine and
            sslContextConscrypt = (OpenSSLContextImpl) Conscrypt.newPreferredSSLContextSpi();
            sslContextConscrypt.engineInit(km,  tm, null);
            return sslContextConscrypt;
        } catch (Exception ex){
            System.out.println("Exception: " + ex.getMessage());

        }

        return null;
    }

    // Thread of server
    public void run(){

        try{
            InitConscrypt();
            createSSLContextConscrypt();
            SSLServerSocketFactory factory=this.sslContextConscrypt.engineGetServerSocketFactory();
            SSLServerSocket sslServerSocket =  (SSLServerSocket)factory.createServerSocket(port);
            System.out.println("SSL server started");
            while(!isServerDone){
                System.out.println("Waiting for connection....");
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                System.out.println("Received connection pasoing to Thread...");
                //System.out.println("Received connection pasoing to Thread...");
                new ServerThread(sslSocket).start();
            }
        } catch (Exception ex){
            System.out.println("Exception: " + ex.getMessage());
        }
    }
    // Thread handling the socket from client
    static class ServerThread extends Thread implements HandshakeCompletedListener {
        private static byte [] ekm;
        // Hanshake comlete listner

        // Hanshake comlete listner
        @Override
        public void handshakeCompleted(HandshakeCompletedEvent event) {
            try {
                //SSLSocket sslSocket=event.getSocket();
                System.out.println("handshake completed successful");

                //System.out.println("handshake completed successful");
                //byte [] b=null;
                //Call Conscrypt API to export keying material
                //byte [] output= new byte[32];
                //String lable= "EXPORTER-HTTP-Transport-Authentication-HMAC";
                //ekm=Conscrypt.exportKeyingMaterial(sslSocket, "master secret",b , EKMlabelLength);
                //System.out.println("EKM="+bytesToHex(ekm));
            }
            catch(Exception e) {
                System.out.println("Error in handshake ");
                System.out.println("\"Error in handshake \"+" + e.getMessage());

                //e.printStackTrace();
                //LOGGER.info("Error Error in handshake : "+e.getMessage());
            }
        }

        private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

        public static String bytesToHex(byte[] bytes) {
            byte[] hexChars = new byte[bytes.length * 2];
            for (int j = 0; j < bytes.length; j++) {
                int v = bytes[j] & 0xFF;
                hexChars[j * 2] = HEX_ARRAY[v >>> 4];
                hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
            }
            return new String(hexChars, UTF_8);
        }
        private SSLSocket sslSocket = null;

        public static  PublicKey peerPublicKey;
        ServerThread(SSLSocket sslSocket){
            this.sslSocket = sslSocket;

        }
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

        @Override
        public void run(){

            //sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());
            try{
                // Start handshake
                this.sslSocket.addHandshakeCompletedListener(this);
                this.sslSocket.startHandshake();

                // Get session after the connection is established

                if (Conscrypt.isConscrypt(sslSocket)) {
                    Conscrypt.getApplicationProtocol(sslSocket);
                    System.out.println("Provider is Conscrypt");

                }
                System.out.println("Serevr SSLSession :");




                // Start handling application content
                InputStream inputStream = sslSocket.getInputStream();
                OutputStream outputStream = sslSocket.getOutputStream();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream,UTF_8));
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream,UTF_8));
                String line = null;
                String u="";
                String a="";
                String p="";
                while((line = bufferedReader.readLine()) != null){
                    System.out.println(line);
                    //Transport-Authentication = transp-auth-scheme *( OWS ";" OWS parameter )
                    //transp-auth-scheme       = token
                    //parameter                = token "=" ( token / quoted-string )

                    if(line.contains("Transport-Authentication")) {
                        String[] ArrSplitPT=line.split(":");
                        //List<String> ArraySplitPT= Splitter.on(':').splitToList(line);
                        if(ArrSplitPT.length>1 && (line.contains("HMAC")  || line.contains("Signature") ) ) {

                            System.out.println("Serevr received Transport-Authentication Header from Client!");
                            if(line.contains("HMAC")) {

                                byte [] b=null;
                                if(ExporterLabelArray.length>1 && !ExporterLabelArray[0].equals("") ){
                                    ekm=Conscrypt.exportKeyingMaterial(sslSocket, ExporterLabelArray[0],b , EKMlabelLength);
                                    System.out.println("HMAC EKM="+bytesToHex(ekm));
                                }
                                else{
                                    System.out.println("Invalid selection of Signature Algorithum");
                                    printWriter.print("HTTP/1.1 No valid Algorithum Selected  400\r\n");
                                    printWriter.flush();
                                }

                                System.out.println("Transport-Authentication use HMAC !");
                                int inedxHMAC=line.indexOf("HMAC");
                                System.out.println("Lets find a,u and pIndex of HMAC ="+Integer.toString(inedxHMAC));
                                int index=line.indexOf("u=");
                                int indexFirstColon=line.indexOf(";");
                                u=line.substring(index+2, indexFirstColon);
                                if(u.equals("")){
                                    printWriter.print("HTTP/1.1 No valid Scheme found 400\r\n");
                                    printWriter.flush();
                                }
                                System.out.println("u ="+u);

                                //line=line.substring(indexFirstColon);
                                line=line.substring(indexFirstColon+1);

                                index=line.indexOf("a=");
                                indexFirstColon=line.indexOf(";");
                                a=line.substring(index+2, indexFirstColon);
                                if(a.equals("")){
                                    printWriter.print("HTTP/1.1 No valid Scheme found 400\r\n");
                                    printWriter.flush();
                                }
                                System.out.println("a ="+a);
                                line=line.substring(indexFirstColon+1);
                                //index=line.indexOf("p=");
                                indexFirstColon=line.indexOf("");
                                //System.out.println("line="+line+" index="+index+" indexFirstColon="+indexFirstColon);
                                p=line.substring(indexFirstColon+3);
                                if(p.equals("")){
                                    printWriter.print("HTTP/1.1 No valid Scheme found 400\r\n");
                                    printWriter.flush();
                                }
                                System.out.println("p="+p);
                                System.out.println("now checking the username and public key=");
                                byte[] usernamedecode = Base64.getDecoder().decode(u);
                                String usernamestr = new String(usernamedecode, StandardCharsets.UTF_8);
                                System.out.println("usernamedecode="+usernamestr);

                                //store user namename of client and its public key
                                //System.out.println("sslSocket.getSession().getPeerCertificateChain()"+sslSocket.getSession().getPeerCertificateChain());
                                SSLSession ss2=sslSocket.getHandshakeSession();

                                System.out.println("getHandshakeSession="+ss2);
                                if (ss2 != null) {
                                    System.out.println("getPeerHost="+ss2.getPeerHost());

                                    Certificate[] clientCerts=ss2.getPeerCertificates();
                                    System.out.println("clientCerts="+clientCerts.length);
                                    //Certificate [] clientCerts=sslSocket.getSession().getPeerCertificates();
                                    System.out.println("reading clientCerts");

                                    System.out.println("Certs retrieved: " + clientCerts.length);
                                    for ( Certificate cert : clientCerts) {
                                        System.out.println("Certificate is: " + cert);
                                        if(cert !=null) {
                                            try {
                                                PublicKey pu=cert.getPublicKey();
                                                System.out.println("publickey="+pu);
                                            }
                                            catch(Exception e) {
                                                System.out.println("Exception printing certificates");
                                            }
                                        }
                                    }
                                }
                                System.out.println("clientPublicKey="+peerPublicKey);

                                //Pass the request ot Destination server
                            }
                            else if(line.contains("Signature")) {

                                byte [] b=null;
                                if(ExporterLabelArray.length>1 && !ExporterLabelArray[1].equals("") ){

                                    // Export Keying material from JNI wrapper
                                    ekm=Conscrypt.exportKeyingMaterial(sslSocket, ExporterLabelArray[1],b , EKMlabelLength);
                                    System.out.println("Signature EKM="+bytesToHex(ekm));
                                }
                                System.out.println("Transport-Authentication use SIgnature");
                                int inedxHMAC=line.indexOf("Signature");
                                System.out.println("Lets find a,u and pIndex of Signature ="+Integer.toString(inedxHMAC));
                                int index=line.indexOf("u=");
                                int indexFirstColon=line.indexOf(";");
                                u=line.substring(index+2, indexFirstColon);
                                System.out.println("u ="+u);
                                line=line.substring(indexFirstColon+1);

                                index=line.indexOf("a=");
                                indexFirstColon=line.indexOf(";");
                                a=line.substring(index+2, indexFirstColon);
                                System.out.println("a ="+a);
                                line=line.substring(indexFirstColon+1);
                                //index=line.indexOf("p=");
                                indexFirstColon=line.indexOf("");
                                p=line.substring(indexFirstColon+3);
                                System.out.println("p="+p);


                                //Pass the request ot Destination server
                                //String tunnelHost = "localhost";
                                //int tunnelPort = Integer.getInteger("7333").intValue();
                                //Socket tunnel = new Socket(tunnelHost, tunnelPort);
                                //tunnel.close();

                            }
                            else{
                                printWriter.print("HTTP/1.1 No valid Scheme found 400\r\n");
                                printWriter.flush();

                            }

                        }
                    }

                    if(line.trim().isEmpty()){
                        break;
                    }
                }

                // Write data
                String reply = "HTTP/1.0 200 Connection Established\r\n";
                System.out.println("Server sending: " + reply);
                printWriter.print(reply);
                printWriter.flush();
                System.out.println("---------------------------------------------------------------");

                //sslSocket.close();
            } catch (Exception ex) {
                ex.printStackTrace();

                System.out.println("Exception: " + ex.getMessage());
                //LOGGER.info("Error run socket processing: "+ex.getMessage());
            }
        }
    }
}