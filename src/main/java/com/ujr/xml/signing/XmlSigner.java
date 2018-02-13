package com.ujr.xml.signing;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class XmlSigner {
	
	private Document doc = null;
	private File fileXml = null;
	private File fileXsd = null;
	
	public XmlSigner(File fileXsd, File fileXml) {
		try {
			this.fileXsd = fileXsd;
			this.fileXml = fileXml;
			
			// Loading XML and its XSD
	    	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	    	SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
	    	Schema schema = schemaFactory.newSchema(fileXsd);
	    	// Schema it is necessary in order to be possible to identify the ID attributes as an ID Type, otherwise and Exception is thrown
	    	// If the ID of the Signed element were not used, that this...
	    	// The whole document it is being signed, it is not strictly necessary load the XML's XSD
	    	dbf.setSchema(schema);
	    	dbf.setNamespaceAware(true);
	    	doc = dbf.newDocumentBuilder().parse(fileXml);
		} catch (SAXException | IOException | ParserConfigurationException e1) {
			throw new RuntimeException(e1);
		}
	}
	
	public XmlSigner(File fileXml) {
		try {
			this.fileXml = fileXml;
			
			// Loading XML and its XSD
	    	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	    	dbf.setNamespaceAware(true);
	    	doc = dbf.newDocumentBuilder().parse(fileXml);
		} catch (SAXException | IOException | ParserConfigurationException e1) {
			throw new RuntimeException(e1);
		}
	}
	
	public void signXml()  {
		this.signXmlElementId(null);
	}
	
	@SuppressWarnings("unchecked")
	public void signXmlElementId(String ID)  {
		if (ID != null && this.fileXsd == null) {
			throw new RuntimeException("When signing parts of XML using its ID Element, it is necessary also inform the XSD of the XML in question!");
		}
		
		try {
			// Factory XML Signing
	    	XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
	    	
	    	// Identifies the ID element to signed (if specified)
	    	String referencedURI = "";
	    	Node sigParent = doc.getDocumentElement();
	    	if ( ID != null ) {
	    		XPathFactory factory = XPathFactory.newInstance();
	            XPath xpath = factory.newXPath();
	            XPathExpression expr = xpath.compile(
                        String.format("//*[@ID='%s']", ID)
                );
	            NodeList nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
	            
                if (nodes.getLength() == 0) {
                	throw new RuntimeException("Can't find node with id: " + ID);
                }
 
                Node nodeToSign = nodes.item(0);
                sigParent       = nodeToSign.getParentNode();	
                referencedURI   = "#" + ID;
	    	}
	    	
	    	// Reading the Keystore to load the X509 Certificate that contains the private key to sign the XML
	    	// and to add the Public part of the Certificate to XML message 
	    	KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			FileInputStream instream = new FileInputStream(new File("/home/ujunior/eclipse-workspace-oxygen/xml-signing-encrypt/cert/ualter-keystore.jks"));
	    	keyStore.load(instream, "ualter".toCharArray());
	    	KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry("ualterjunior", new KeyStore.PasswordProtection("ualter".toCharArray()));
	    	X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
	    	
	    	// Identifies the data that will be digested and signed
	    	// Signing the whole document, so a URI of "" signifies that
	    	Reference ref = fac.newReference(
	    			referencedURI, 
	    			fac.newDigestMethod(DigestMethod.SHA1,null),
	    			Collections.singletonList(fac.newTransform(Transform.ENVELOPED,(TransformParameterSpec)null)),
	    			null,
	    			null
	    	);
	    	// Creates the SignedInfo object that the signature is calculated over
	    	// Assembled by creating and passing as parameters each of its components: 
	    	//           the CanonicalizationMethod, the SignatureMethod, and a list of References
	    	SignedInfo signedInfo = fac.newSignedInfo(
	    			fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,(C14NMethodParameterSpec)null), 
	    			fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), 
	    			Collections.singletonList(ref)
	    	);
	    	
	    	// Creating the KeyInfo that will contain the X509Data (the Certificate and the Subject Distinguished Name)
	    	@SuppressWarnings("rawtypes")
			List x509Content = new ArrayList();
	    	KeyInfoFactory kif = fac.getKeyInfoFactory();
	    	X509IssuerSerial x509IssuerSerial = kif.newX509IssuerSerial(cert.getSubjectX500Principal().getName(), cert.getSerialNumber());
	    	x509Content.add(cert.getSubjectX500Principal().getName());
	    	x509Content.add(cert);
	    	x509Content.add(x509IssuerSerial);
	    	X509Data xd = kif.newX509Data(x509Content);
	    	KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(xd));
	    	
	    	// Create a DOMSignContext and specify the RSA PrivateKey and
	    	// location of the resulting XMLSignature's parent element. 
	    	DOMSignContext dsc = new DOMSignContext(
	    			keyEntry.getPrivateKey(), 
	    			sigParent
	    	);
	    	
	    	// Create the XMLSignature, but don't sign it yet.
	    	XMLSignature signature = fac.newXMLSignature(signedInfo, keyInfo);
	    	
	    	// Marshal, generate, and sign the enveloped signature.
	    	signature.sign(dsc);
	    	
	    	if ( ID != null ) {
	    		System.out.println("Signed #" + ID);
	    	} else {
	    		System.out.println("Signed XML");
	    	}
	    	
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException 
				| InvalidAlgorithmParameterException | UnrecoverableEntryException | MarshalException 
				| XMLSignatureException | XPathExpressionException e) {
			// TODO
			e.printStackTrace();
		}
	}
	
	public void writeSignedXmlTo(OutputStream os)  {
		try {
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(doc), new StreamResult(os));
		} catch (TransformerException e) {
			throw new RuntimeException(e);
		}
		
	}
	
	public Map<String,Boolean> checkSigning() {
		Map<String,Boolean> signatures = new HashMap<String,Boolean>();
		try {
        	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        	SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
	    	Schema schema = schemaFactory.newSchema(fileXsd);
	    	dbf.setSchema(schema);
        	dbf.setNamespaceAware(true);
			Document doc = dbf.newDocumentBuilder().parse(fileXml);
			
			NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
			if (nl.getLength() == 0) {
			    throw new RuntimeException("Cannot find Signature element");
			}
			
			for(int i = 0; i < nl.getLength(); i++) {
				
				Element elementSignature  = (Element)nl.item(i);
				Element elementSignedInfo = (Element)elementSignature.getElementsByTagName("SignedInfo").item(0);
				Element elementReference  = (Element)elementSignedInfo.getElementsByTagName("Reference").item(0);
				String  uriSignature      = elementReference.getAttribute("URI"); 
				
				DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), nl.item(i));
				XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
				// Unmarshal the XMLSignature.
				XMLSignature signature = fac.unmarshalXMLSignature(valContext);
				// Validate the XMLSignature.
				boolean coreValidity = signature.validate(valContext);
				
				signatures.put(uriSignature, coreValidity);
				
			}
			
		} catch (SAXException | IOException | ParserConfigurationException | MarshalException | XMLSignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return signatures;
	}

}
