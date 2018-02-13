package com.ujr.xml.signing.encrypt;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.net.URL;
import java.util.Map;

import com.ujr.xml.signing.XmlSigner;


/**
 *
 */
public class App 
{
    public static void main( String[] args )
    {
    	signXml();
    	
    	checkSigning();
    }

	private static void signXml() {
		
		URL urlXsd = Thread.currentThread().getContextClassLoader().getResource("Deposits.xsd");
    	File fileXsd = new File(urlXsd.getPath());
		
		URL urlXml = Thread.currentThread().getContextClassLoader().getResource("Deposits.xml");
    	File fileXml = new File(urlXml.getPath());
    	
    	XmlSigner xmlSigner = new XmlSigner(fileXsd, fileXml);
    	
    	xmlSigner.signXmlElementId("total");
    	xmlSigner.signXmlElementId("deposit");
    	
    	try {
    		xmlSigner.writeSignedXmlTo(System.out);
			xmlSigner.writeSignedXmlTo(new FileOutputStream("./src/main/resources/signed-Deposits.xml"));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static void checkSigning() {
		URL urlXsd = Thread.currentThread().getContextClassLoader().getResource("Deposits.xsd");
    	File fileXsd = new File(urlXsd.getPath());
    	
    	URL urlSignedXml = Thread.currentThread().getContextClassLoader().getResource("signed-Deposits.xml");
    	File signedFileXml = new File(urlSignedXml.getPath());
    	
    	XmlSigner xmlSigner = new XmlSigner(fileXsd, signedFileXml);
    	
    	Map<String,Boolean> signatures = xmlSigner.checkSigning();
    	
    	System.out.println("\n\nTotal Signatures: " + signatures.size());
		signatures.forEach((k,v) -> System.out.format(" - URI %s = Check Sign: %s \n",k,(v ? "OK" : "NOT")));
	}

	
}
