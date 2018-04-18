/*************************************************************************
 *	  @file Test.java
 *	  @brief Tests a SSL/TLS connection to the Apriva server
 *	  @date 09/22/2016
 *	  @version 1.3
 *
 *	  Copyright (c) 2016 by Apriva
 *	  All rights reserved
 *
 *	  CONFIDENTIAL AND PROPRIETARY
 *
 *	  This software may contain confidential and trade secret
 *	  information and technology and may not be used, disclosed or
 *	  made available to others without the permission of Apriva.
 *	  Copies may only be made with permission and must contain the
 *	  above copyright notice. Neither title to the software nor
 *	  ownership of the software is hereby transferred.
 *************************************************************************/
import java.io.*;
import java.security.*;
import java.util.Enumeration;

import javax.net.ssl.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.sun.crypto.provider.JceKeyStore;

class Test {
	// Create an SSL socket factory to use to connect to the Apriva server with
	// Read the appropriate certificate chains and keys from files into the SSL factory
	private String BDK = "0123456789ABCDEFFEDCBA9876543210";
	
	protected static javax.net.ssl.SSLSocketFactory createSSLFactory () {

		try {
			// *** Client Side Certificate *** //
			System.out.println ("2. Loading p12 file");

			// Load the certificate file into the keystore
			KeyStore keystore = KeyStore.getInstance("JKS");
			System.out.println("keystore == " + keystore);
			FileInputStream inputFile = new FileInputStream (clientCertFileName);

			char [] clientPassphrase = clientCertPassword.toCharArray ();
			keystore.load (inputFile, clientPassphrase);

			// Create the factory
			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
			keyManagerFactory.init (keystore, clientPassphrase);

			//The following section demonstrates how to configure the server trust for production.
			//It is not required for test environments and that is why the code is commented out.
			//Each line required will have the term "JKS line needed for production" following it.
			//The AprivaTrust.jks file included in this project can be used for production.
			
			// *** Server Trust *** //
			//System.out.println ("3. Loading JKS file");
			//KeyStore truststore = KeyStore.getInstance("JKS"); //JKS line needed for production
			//FileInputStream trustInputFile = new FileInputStream (serverTrustFileName); //JKS line needed for production

			//char [] serverTrustPassphrase = serverTrustPassword.toCharArray (); //JKS line needed for production
			//truststore.load (trustInputFile, serverTrustPassphrase); //JKS line needed for production

			//TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); //JKS line needed for production
			//tmf.init (truststore); //JKS line needed for production

			//TrustManager[] trustManagers = tmf.getTrustManagers (); //JKS line needed for production

			// Create the SSL context and use it to initialize the factory
			SSLContext ctx = SSLContext.getInstance("TLS");
			//ctx.init (keyManagerFactory.getKeyManagers(), trustManagers, null); //JKS line needed for production
			ctx.init (keyManagerFactory.getKeyManagers(), null, null); //This line should be removed in production, the line above replaces it

			SSLSocketFactory sslFactory = ctx.getSocketFactory();
			return sslFactory;

		} catch (Exception e) {

			e.printStackTrace ();
		}

		return null;
	}

	// Perform the test by connecting to the Apriva server
	protected static void test (String host, int port) {

		try {
			// Create an SSL factory and use it to create an SSL socket
			SSLSocketFactory sslFactory = createSSLFactory ();

			System.out.println ("4. Connecting to " + host +  " port " + port);
			SSLSocket socket = (SSLSocket) sslFactory.createSocket (host, port);

			// Connect
			socket.startHandshake();

			// Send the XML request to the server
			OutputStream outputstream = socket.getOutputStream();
			OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);

			BufferedWriter bufferedWriter = new BufferedWriter(outputstreamwriter);

			String testXML = "<AprivaPosXml DeviceAddress=\"7771314\">" + 
										  "<Credit MessageType=\"Request\" Version=\"5.0\" ProcessingCode=\"Sale\">" + 
										     "<Stan>1</Stan>"+
										     "<CardPresent>YES</CardPresent>" + 
										     "<EntryMode>Manual</EntryMode>" + 
										     "<EntryModeType>Standard</EntryModeType>" + 
										     "<ExpireDate>17/08</ExpireDate>" + 
										     "<Amount>1.00</Amount>" + 
										     "<AccountNumber>4111111111111111</AccountNumber>" + 
										   "</Credit>" + 
										  "</AprivaPosXml>";
			
			
			System.out.println ("5. Sending Request --->>>>>>");
			System.out.println (formatPrettyXML(testXML));
			
			bufferedWriter.write (testXML);
			bufferedWriter.flush ();

			System.out.println ("6. Waiting for Response <<<<<<--------");
			InputStream inputstream = socket.getInputStream();
			InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
			BufferedReader bufferedReader = new BufferedReader(inputstreamreader);

			String line = null;
			while ((line = bufferedReader.readLine()) != null) {
				System.out.println(formatPrettyXML(line));
			}

		} catch (Exception e) {
			e.printStackTrace ();
		}
	}

	protected static String formatPrettyXML(String unformattedXML) {
		String prettyXMLString = null;
		
		try {
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			StreamResult result = new StreamResult(new StringWriter());
			StreamSource source = new StreamSource(new StringReader(unformattedXML));
			transformer.transform(source, result);
			prettyXMLString = result.getWriter().toString();			
		} catch (TransformerConfigurationException e) {
			System.out.println("Unable to transform XML " + e.getMessage());
		} catch (TransformerFactoryConfigurationError e) {
			System.out.println("Unable to transform XML " + e.getMessage());
		} catch (TransformerException e) {
			System.out.println("Unable to transform XML " + e.getMessage());
		}
		
		return prettyXMLString;
	}
	
	// Main Function (EntryPoint)
	public static void main(String[] args) throws IOException
	{	
		// Display the current local directory
		String current = new java.io.File( "." ).getCanonicalPath();
	    System.out.println("Current dir: "+current);
		
		String HostName = "aibapp53.aprivaeng.com";
		String HostPort = "11098";
		
		// The file containing the client certificate, private key, and chain
//		clientCertFileName = "cert/AprivaDeveloper.p12";
//		clientCertFileNameBKS = "cert/AprivaDeveloperBKS.p12";
		clientCertFileName = "cert/LimePC11.p12";
		clientCertFileNameBKS = "cert/LimePC11BKS.p12";
		clientCertPassword = "P@ssword";
		jks2bks(clientCertFileName, clientCertPassword, clientCertFileNameBKS, clientCertPassword);
		System.out.println("jsk to bks is ok!");

		// The file containing the server trust chain
		serverTrustFileName = "cert/AprivaTrust.jks";
		serverTrustPassword = "P@ssword";

		String host = HostName;
		int port = Integer.parseInt(HostPort);
		System.out.println ("Java Sample App v1.2 - AIB .53");
		System.out.println ("1. Running Test");
		test (host, port);
	}

	
	static String clientCertFileName;
	static String clientCertPassword;
	static String clientCertFileNameBKS;
	static String serverTrustFileName;
	static String serverTrustPassword;
	
	public static void jks2bks(String jkspath, String jkspass, String bkspath,
			String bkspass) {
		FileInputStream jksFileInputStream = null;
		FileOutputStream bksFileOutputStream = null;
		try {
			KeyStore jksKeyStore = KeyStore.getInstance("JKS");
			jksFileInputStream = new FileInputStream(jkspath);
			jksKeyStore.load(jksFileInputStream, jkspass.toCharArray());

			KeyStore bksKeyStore = KeyStore.getInstance("BKS",
					new BouncyCastleProvider());
			Security.addProvider(new BouncyCastleProvider());
			bksFileOutputStream = new FileOutputStream(bkspath);
			bksKeyStore.load(null, bkspass.toCharArray());

			Enumeration aliases = jksKeyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = (String) aliases.nextElement();

				if (jksKeyStore.isCertificateEntry(alias)) {
					System.out.println("isCertificateEntry:" + alias);
					java.security.cert.Certificate certificate = jksKeyStore
							.getCertificate(alias);
					bksKeyStore.setCertificateEntry(alias, certificate);
				} else if (jksKeyStore.isKeyEntry(alias)) {
					System.out.println("isKeyEntry:" + alias);
					Key key = jksKeyStore.getKey(alias, jkspass.toCharArray());
					java.security.cert.Certificate[] certificates = jksKeyStore
							.getCertificateChain(alias);
					bksKeyStore.setKeyEntry(alias, key, bkspass.toCharArray(),
							certificates);
				}
			}
			bksKeyStore.store(bksFileOutputStream, bkspass.toCharArray());

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (jksFileInputStream != null) {
				try {
					jksFileInputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (bksFileOutputStream != null) {
				try {
					bksFileOutputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
}



