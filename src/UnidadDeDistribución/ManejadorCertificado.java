//David Felipe Niño Romero		201412734 
//Nicolás Mateo Hernández Rojas 		 201412420

package UnidadDeDistribución;
import java.awt.FontFormatException;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Certificate;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.tls.HeartbeatExtension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

public class ManejadorCertificado 
{
	/**
	 * 
	 * @return PublicKey con la llave pública del certificado del servidor
	 */
	public static PublicKey creationYProcesamiento(KeyPair llaveAsim, OutputStream outputStream, InputStream inputStream, PrintWriter pw, BufferedReader bf)
	{
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		Security.addProvider(new BouncyCastleProvider());

		try 
		{
			ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(llaveAsim.getPrivate());

			byte[] publickeyb= llaveAsim.getPublic().getEncoded();
			
			SubjectPublicKeyInfo subPubKeyInfo = new SubjectPublicKeyInfo( sigAlgId, publickeyb);


			Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
			Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);

			X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
					new X500Name("CN=EmisorName"), 
					BigInteger.ONE, 
					startDate, endDate, 
					new X500Name("CN=SubjectName"), 
					llaveAsim.getPublic());

			X509CertificateHolder certHolder = v3CertGen.build(sigGen);

			pw.println("CERTCLNT");
			byte [] certificado = certHolder.getEncoded();
			outputStream.write(certificado);
			outputStream.flush();				

			String rta = bf.readLine();
			if ((!rta.contains(":")) || (!rta.split(":")[0].equals("ESTADO")))
			{
		        throw new Exception("Formato de mensaje inesperado.");
		    }
			rta = rta.split(":")[1];
			if (!rta.equals("OK"))
			{
		        throw new Exception("Error enviando certificado.");
		    }
			
			rta = bf.readLine();
			
			if(!rta.equals("CERTSRV"))
			{
				throw new Exception("Respuesta inesperada.");
			}	
		} 
		catch (Exception e)
		{
			e.printStackTrace();
		}	
		
		X509Certificate certificadoServidor;
		
		try 
		{
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			byte[] certificadoServidorBytes= new byte[2048];
			
			inputStream.read(certificadoServidorBytes);
			InputStream is = new ByteArrayInputStream(certificadoServidorBytes);
			certificadoServidor = ((X509Certificate)certFactory.generateCertificate(is));
			pw.println("ESTADO:OK");
			return certificadoServidor.getPublicKey();
		} 
		catch (Exception ce) 
		{
			pw.println("ESTADO:ERROR");
			ce.printStackTrace();
		}

		return null;
	}
}
