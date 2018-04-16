//David Felipe Niño Romero		201412734 
//Nicolás Mateo Hernández Rojas 		 201412420

package UnidadDeDistribución;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class CifradorAsimetricoRSA
{
	private final static String ALGORITMO="RSA";
	private KeyPair keyPair;

	public CifradorAsimetricoRSA()
	{
		KeyPairGenerator generator;
		try
		{
			generator = KeyPairGenerator.getInstance(ALGORITMO);
			generator.initialize(1024);
			keyPair = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) 
		{
			e.printStackTrace();
		}
		
	}
	
	public byte[] cifrar() 
	{
		try 
		{
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			BufferedReader stdIn =	new BufferedReader(new InputStreamReader(System.in));
			String pwd = stdIn.readLine();
			byte [] clearText = pwd.getBytes();
			String s1 = new String (clearText);
			System.out.println("clave original: " + s1);
			cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
			long startTime = System.nanoTime();
			byte [] cipheredText = cipher.doFinal(clearText);
			long endTime = System.nanoTime();
			System.out.println("clave cifrada: " + cipheredText);
			System.out.println("Tiempo asimetrico: " + (endTime - startTime));
			return cipheredText;
		}
		catch (Exception e)
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}

	public byte[] descifrar (byte[] cipheredText) 
	{
		try 
		{
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			byte [] clearText = cipher.doFinal(cipheredText);
			return clearText;
		}
		catch (Exception e) 
		{
			System.out.println("Excepcion: " + e.getMessage());
		}
		return null;
	}

	public KeyPair darLlave() 
	{
		return keyPair;
	}
	
	public PrivateKey getPrivate()
	{
		return keyPair.getPrivate();
	}

	public PublicKey getPublic()
	{
		return keyPair.getPublic();
	}
	
	public static byte[] cifrar(PublicKey llave, byte[] msg) throws Exception
	{
		Cipher cipher = Cipher.getInstance(ALGORITMO);
		cipher.init(Cipher.ENCRYPT_MODE, llave);
		byte [] msgC = cipher.doFinal(msg);
		return msgC;
	}
	
	public static byte[] descifrar(PublicKey llave, byte[] msgC) throws Exception
	{
		Cipher cipher = Cipher.getInstance(ALGORITMO);
		cipher.init(Cipher.DECRYPT_MODE, llave);
		byte [] msg = cipher.doFinal(msgC);
		return msg;
	}
	
	public static byte[] descifrar(PrivateKey llave, byte[] msgC) throws Exception
	{
		Cipher cipher = Cipher.getInstance(ALGORITMO);
		cipher.init(Cipher.DECRYPT_MODE, llave);
		byte [] msg = cipher.doFinal(msgC);
		return msg;
	}
}
