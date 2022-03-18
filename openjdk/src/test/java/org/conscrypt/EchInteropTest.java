/*
 * Copyright (C) 2021 The Android Open Source Project
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

package org.conscrypt;

import org.conscrypt.com.android.net.module.util.DnsPacket;
import org.conscrypt.testing.Streams;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.NamingException;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.bind.DatatypeConverter;

import sun.misc.IOUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(JUnit4.class)
public class EchInteropTest {

    private static final int TIMEOUT_MILLISECONDS = 30000;

    String[] hostsNonEch = {
            "www.yandex.ru",
            "openstreetmap.org",
            "en.wikipedia.org",
            "web.wechat.com",
            "mirrors.kernel.org",
            "www.google.com",
            "check-tls.akamaized.net", // uses SNI
            "duckduckgo.com", // TLS 1.3
            "deb.debian.org", // TLS 1.3 Fastly
            "tls13.1d.pw", // TLS 1.3 only, no ECH

            "cloudflare-esni.com", // ESNI no ECH
            "enabled.tls13.com", // TLS 1.3 enabled by Cloudflare with ESNI no ECH
            "cloudflare.f-droid.org",
    };
    String[] hostsEch = {
            "crypto.cloudflare.com", // ECH

            // ECH enabled
            "draft-13.esni.defo.ie:8413", // OpenSSL s_server
            "draft-13.esni.defo.ie:8414", // OpenSSL s_server, likely forces HRR as it only likes P-384 for TLS =09
            "draft-13.esni.defo.ie:9413", // lighttpd
            "draft-13.esni.defo.ie:10413", // nginx
            "draft-13.esni.defo.ie:11413", // apache
            "draft-13.esni.defo.ie:12413", // haproxy shared mode (haproxy terminates TLS)
            "draft-13.esni.defo.ie:12414", // haproxy split mode (haproxy only decrypts ECH)
    };
    String[] hosts = new String[hostsNonEch.length + hostsEch.length];

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        Security.insertProviderAt(Conscrypt.newProvider(), 1);
        assertTrue(Conscrypt.isAvailable());
        assertTrue(Conscrypt.isConscrypt(SSLContext.getInstance("TLSv1.3")));
        System.arraycopy(hostsNonEch, 0, hosts, 0, hostsNonEch.length);
        System.arraycopy(hostsEch, 0, hosts, hostsNonEch.length, hostsEch.length);
        prefetchDns(hosts);
    }

    @After
    public void tearDown() throws NoSuchAlgorithmException {
        Security.removeProvider("Conscrypt");
        assertFalse(Conscrypt.isConscrypt(SSLContext.getInstance("TLSv1")));
    }

    @Test
    public void testConnectSocket() throws IOException {
        for (String h : hosts) {
            System.out.println("EchInteroptTest " + h + " =================================");
            String[] hostPort = h.split(":");
            String host = hostPort[0];
            int port = 443;
            if (hostPort.length == 2) {
                port = Integer.parseInt(hostPort[1]);
            }

            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            assertTrue(Conscrypt.isConscrypt(sslSocketFactory));
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
            assertTrue(Conscrypt.isConscrypt(sslSocket));
            boolean setUpEch = false;
            try {
                byte[] echConfigList = TestUtils.readTestFile(h.replace(':', '_') + "-ech-config-list.bin");
                Conscrypt.setUseEchGrease(sslSocket, true);
                Conscrypt.setEchConfigList(sslSocket, echConfigList);
                System.out.println("Enabling ECH Config List and ECH GREASE");
                setUpEch = true;
            } catch (FileNotFoundException e) {
                System.out.println("Enabling ECH GREASE");
                Conscrypt.setUseEchGrease(sslSocket, true);
            }
            sslSocket.setSoTimeout(TIMEOUT_MILLISECONDS);
            sslSocket.startHandshake();
            assertTrue(sslSocket.isConnected());
            AbstractConscryptSocket abstractConscryptSocket = (AbstractConscryptSocket) sslSocket;
            if (setUpEch) {
                assertTrue(h + " should accept ECH", abstractConscryptSocket.echAccepted());
            } else {
                assertFalse(h + " should NOT accept ECH", abstractConscryptSocket.echAccepted());
            }
            sslSocket.close();
        }
    }

    @Test
    public void testEchRetryConfigWithConnectSocket() throws IOException, NamingException {
        for (String h : hostsEch) {
            System.out.println("EchInteroptTest.testEchRetryConfigWithConnectSocket " + h + " =====================");
            String[] hostPort = h.split(":");
            String host = hostPort[0];
            int port = 443;
            if (hostPort.length == 2) {
                port = Integer.parseInt(hostPort[1]);
            }

            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            assertTrue(Conscrypt.isConscrypt(sslSocketFactory));
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
            assertTrue(h + " should use Conscrypt", Conscrypt.isConscrypt(sslSocket));

            byte[] echConfigList = Conscrypt.getEchConfigListFromDns(host, port);
            if (echConfigList == null) {
                System.out.println("No ECH Config List found in DNS: " + h);
                continue;
            }
            // corrupt the key while leaving the SNI intact
            echConfigList[20] = (byte) 0xff;
            echConfigList[21] = (byte) 0xff;
            echConfigList[22] = (byte) 0xff;
            echConfigList[23] = (byte) 0xff;
            Conscrypt.echPbuf("testEchRetryConfigWithConnectSocket corrupted " + h, echConfigList);
            Conscrypt.setEchConfigList(sslSocket, echConfigList);

            try {
                sslSocket.setSoTimeout(TIMEOUT_MILLISECONDS);
                sslSocket.startHandshake();
                sslSocket.close();
                fail("Used corrupt ECH Config List, should not connect to " + h);
            } catch (EchRejectedException e) {
                byte[] echRetryConfig = Conscrypt.getEchRetryConfigList(sslSocket);
                assertNotNull(echRetryConfig);
                sslSocket.close();
                Conscrypt.echPbuf("testEchRetryConfigWithConnectSocket getEchRetryConfigList(sslSocket)", echRetryConfig);
                SSLSocket sslSocket2 = (SSLSocket) sslSocketFactory.createSocket(host, port);
                Conscrypt.setEchConfigList(sslSocket2, echRetryConfig);
                sslSocket2.setSoTimeout(TIMEOUT_MILLISECONDS);
                sslSocket2.startHandshake();
                assertTrue(h + " should connect with ECH Retry Config", sslSocket2.isConnected());
                AbstractConscryptSocket abstractConscryptSocket = (AbstractConscryptSocket) sslSocket2;
                assertTrue(h + " should use ECH with Retry Config", abstractConscryptSocket.echAccepted());
                sslSocket2.close();

            } catch (SSLHandshakeException e) {
                System.out.println(e.getMessage().contains(":ECH_REJECTED ") + " | " + e.getMessage());
                e.printStackTrace();
                fail(e.getMessage());
            }
        }
    }

    @Rule
    public ExpectedException echRejectedExceptionRule = ExpectedException.none();

    @Test
    public void testEchConfigOnNonEchHosts() throws IOException {
        for (String h : hostsNonEch) {
            System.out.println("testEchConfigOnNonEchHosts " + h + " ====================================");
            String[] hostPort = h.split(":");
            String host = hostPort[0];
            int port = 443;
            if (hostPort.length == 2) {
                port = Integer.parseInt(hostPort[1]);
            }

            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            assertTrue(Conscrypt.isConscrypt(sslSocketFactory));
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
            assertTrue(Conscrypt.isConscrypt(sslSocket));

            byte[] echConfigList = TestUtils.readTestFile("draft-13.esni.defo.ie_12414-ech-config-list.bin");
            Conscrypt.setEchConfigList(sslSocket, echConfigList);

            echRejectedExceptionRule.expect(SSLHandshakeException.class);
            echRejectedExceptionRule.expectMessage("ECH_REJECTED");
            sslSocket.setSoTimeout(TIMEOUT_MILLISECONDS);
            sslSocket.startHandshake();
            assertTrue(sslSocket.isConnected());
            AbstractConscryptSocket abstractConscryptSocket = (AbstractConscryptSocket) sslSocket;
            assertTrue(h + " should accept ECH", abstractConscryptSocket.echAccepted());
            sslSocket.close();
        }
    }

    @Test
    public void testConnectHttpsURLConnection() throws IOException {
        for (String host : hosts) {
            URL url = new URL("https://" + host);
            System.out.println("EchInteroptTest " + url + " =================================");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            SSLSocketFactory delegateSocketFactory = connection.getSSLSocketFactory();
            assertTrue(Conscrypt.isConscrypt(delegateSocketFactory));
            try {
                byte[] echConfigList = TestUtils.readTestFile(host.replace(':', '_') + "-ech-config-list.bin");
                connection.setSSLSocketFactory(new EchSSLSocketFactory(delegateSocketFactory, echConfigList));
                System.out.println("Enabling ECH Config List and ECH GREASE");
            } catch (FileNotFoundException e) {
                System.out.println("Enabling ECH GREASE");
                connection.setSSLSocketFactory(new EchSSLSocketFactory(delegateSocketFactory, true));
            }
            // Cloudflare will return 403 Forbidden (error code 1010) unless a User Agent is set :-|
            connection.setRequestProperty("User-Agent", "Conscrypt EchInteropTest");
            connection.setConnectTimeout(0); // blocking connect with TCP timeout
            connection.setReadTimeout(0);
            if (connection.getResponseCode() != 200) {
                System.out.println(new String(Streams.readFully(connection.getErrorStream())));
            }
            connection.getContent();
            assertEquals(200, connection.getResponseCode());
            assertEquals("text/html", connection.getContentType().split(";")[0]);
            System.out.println(host + " " + connection.getCipherSuite());
            assertTrue(connection.getCipherSuite().startsWith("TLS"));
            connection.disconnect();
        }
    }

    @Test
    public void testConnectCloudflareTrace() throws IOException {
        String host = "crypto.cloudflare.com";
        String urlString = "https://" + host + "/cdn-cgi/trace";
        System.out.println("EchInteroptTest " + urlString + " =================================");
        URL url = new URL(urlString);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        SSLSocketFactory delegateSocketFactory = connection.getSSLSocketFactory();
        assertTrue(Conscrypt.isConscrypt(delegateSocketFactory));
        // TODO get working with built-in automatic DNS
        byte[] echConfigList = Conscrypt.getEchConfigListFromDns(host, 443);
        connection.setSSLSocketFactory(new EchSSLSocketFactory(delegateSocketFactory, echConfigList));
        // Cloudflare will return 403 Forbidden (error code 1010) unless a User Agent is set :-|
        connection.setRequestProperty("User-Agent", "Conscrypt EchInteropTest");
        connection.setConnectTimeout(0); // blocking connect with TCP timeout
        connection.setReadTimeout(0);
        if (connection.getResponseCode() != 200) {
            System.out.println(new String(Streams.readFully(connection.getErrorStream())));
        }
        assertEquals(200, connection.getResponseCode());
        assertEquals("text/plain", connection.getContentType().split(";")[0]);
        String trace = new String(IOUtils.readAllBytes(connection.getInputStream()));
        System.out.println(urlString + " " + connection.getCipherSuite() + ":\n" + trace);
        assertTrue(connection.getCipherSuite().startsWith("TLS"));
        assertTrue("contains sni=encrypted", trace.contains("sni=encrypted"));
        assertFalse("does NOT contain sni=plaintext", trace.contains("sni=plaintext"));
        connection.disconnect();
    }

    @Test
    public void testParseDnsAndConnect() throws IOException, NamingException {
        for (String h : hosts) {
            System.out.println("EchInteropTest.testParseDnsAndConnect " + h + " =================================");
            String[] hostPort = h.split(":");
            String host = hostPort[0];
            int port = 443;
            if (hostPort.length > 1) {
                port = Integer.parseInt(hostPort[1]);
            }
            byte[] echConfigList = Conscrypt.getEchConfigListFromDns(host, port);

            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            assertTrue(Conscrypt.isConscrypt(sslSocketFactory));
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
            assertTrue(Conscrypt.isConscrypt(sslSocket));
            Conscrypt.setUseEchGrease(sslSocket, true);
            if (echConfigList != null) {
                System.out.println("Enabled ECH Config List and ECH GREASE");
            }
            Conscrypt.setEchConfigList(sslSocket, echConfigList);
            sslSocket.setSoTimeout(TIMEOUT_MILLISECONDS);
            sslSocket.startHandshake();
            assertTrue(sslSocket.isConnected());
            AbstractConscryptSocket abstractConscryptSocket = (AbstractConscryptSocket) sslSocket;
            System.out.println(host + " echAccepted " + abstractConscryptSocket.echAccepted());
            if (echConfigList != null) {
                assertTrue(abstractConscryptSocket.echAccepted());
            } else {
                assertFalse(abstractConscryptSocket.echAccepted());
            }
            sslSocket.close();
        }
    }

    @Test
    public void testParseDnsFromFiles() {
        for (String hostString : hosts) {
            System.out.println("EchInteroptTest " + hostString + " =================================");
            String[] h = hostString.split(":");
            String host = h[0];
            if (h.length > 1) {
                if (!"443".equals(h[1])) {
                    host = "_" + h[1] + "._https." + h[0]; // query for non-standard port
                }
            }
            try {
                byte[] dnsAnswer = TestUtils.readTestFile(host + ".bin");
                Conscrypt.echPbuf("DNS Answer", dnsAnswer);
                try {
                    EchDnsPacket echDnsPacket = new EchDnsPacket(dnsAnswer);
                    Conscrypt.echPbuf("ECH Config List", echDnsPacket.getEchConfigList());
                } catch (DnsPacket.ParseException e) {
                    e.printStackTrace();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }

    /**
     * {@code git clone https://github.com/sftcd/echdnsfuzz} into {@code openjdk/src/test/resources/}
     */
    @Test
    public void testEchDnsFuzz() throws IOException {
        URL url = Thread.currentThread().getContextClassLoader().getResource("echdnsfuzz");
        Assume.assumeTrue("https://github.com/sftcd/echdnsfuzz must be cloned into resources", url != null);
        Pattern pattern = Pattern.compile("\\(([0-9a-fA-F\\s]{4,})\\)", Pattern.MULTILINE);
        for (File f : new File(url.getPath()).listFiles()) {
            if (!f.getName().endsWith(".stanza")) {
                continue;
            }
            String stanza = new String(TestUtils.readTestFile("echdnsfuzz/" + f.getName()));
            Matcher m = pattern.matcher(stanza);
            if (!m.find()) {
                System.out.println("== Skipping " + f.getName() + ", didn't find bytes in .stanza file ============");
                continue;
            }
            String bytes = m.group(1).replaceAll(" ", "").replaceAll("\n", "").replaceAll("\t", "");
            System.out.println("== EchInteroptTest.testEchDnsFuzz " + f.getName() + " =============================");
            byte[] rr = DatatypeConverter.parseHexBinary(bytes);
            Conscrypt.echPbuf(f.getName() + " stanza", rr);
            byte[] echConfigList = EchDnsPacket.getEchConfigListFromDnsRR(rr);
            Conscrypt.echPbuf("ECH Config List", echConfigList);
        }
    }

    private static class EchSSLSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private final boolean enableEchGrease;

        private byte[] echConfigList;

        public EchSSLSocketFactory(SSLSocketFactory delegate, boolean enableEchGrease) {
            this.delegate = delegate;
            this.enableEchGrease = enableEchGrease;
        }

        public EchSSLSocketFactory(SSLSocketFactory delegate, byte[] echConfigList) {
            this.delegate = delegate;
            this.enableEchGrease = true;
            this.echConfigList = echConfigList;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }

        @Override
        public Socket createSocket(Socket socket, String host, int port, boolean autoClose)
                throws IOException {
            return setEchSettings(delegate.createSocket(socket, host, port, autoClose));
        }

        @Override
        public Socket createSocket(String host, int port)
                throws IOException, UnknownHostException {
            return setEchSettings(delegate.createSocket(host, port));
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localAddress, int localPort)
                throws IOException, UnknownHostException {
            return setEchSettings(delegate.createSocket(host, port, localAddress, localPort));
        }

        @Override
        public Socket createSocket(InetAddress host, int port)
                throws IOException {
            return setEchSettings(delegate.createSocket(host, port));
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
                throws IOException {
            return setEchSettings(delegate.createSocket(address, port, localAddress, localPort));
        }

        private Socket setEchSettings(Socket socket) {
            SSLSocket sslSocket = (SSLSocket) socket;
            Conscrypt.setUseEchGrease(sslSocket, enableEchGrease);
            Conscrypt.setEchConfigList(sslSocket, echConfigList);
            return sslSocket;
        }
    }

    /**
     * Prime the DNS cache with the hosts that are used in these tests.
     */
    private void prefetchDns(String[] hosts) {
        System.out.println("prefetchDns " + Arrays.toString(hosts));
        for (final String host : hosts) {
            new Thread() {
                @Override
                public void run() {
                    Conscrypt.getEchConfigListFromDns(host);
                    try {
                        InetAddress.getByName(host);
                    } catch (UnknownHostException e) {
                        // ignored
                    }
                }
            }.start();
        }
    }
}
