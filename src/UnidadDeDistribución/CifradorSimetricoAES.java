//David Felipe Niño Romero		201412734 
//Nicolás Mateo Hernández Rojas 		 201412420

package UnidadDeDistribución;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CifradorSimetricoAES
{
	private SecretKey desKey;
	private final static String ALGORITMO = "AES";
	private final static String PADDING="AES/ECB/PKCS5Padding";

	/**
	 * 
	 * @param msjRecibido mensaje a cifrar
	 * @param llave llave con la que se cifra
	 * @return codigo de mensaje cifrado
	 */
	public static byte[] cifrar(String msjRecibido, SecretKey llave) 
	{
		byte[] cipheredText;
		try
		{
			Cipher cipher = Cipher.getInstance(PADDING);

			byte[] clearText = msjRecibido.getBytes();
			String s1 = new	String (clearText);
			System.out.println("clave original: " + s1);
			cipher.init(Cipher.ENCRYPT_MODE, llave);
			long startTime = System.nanoTime();
			cipheredText = cipher.doFinal(clearText);
			long endTime = System.nanoTime();
			String s2 = new	String (cipheredText);
			System.out.println("clave cifrada: " + s2);
			System.out.println("Tiempo: " + (endTime-startTime));
			return cipheredText;
		}
		catch(Exception e) 
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}
	
	public static byte[] cifrarB(byte[] msjRecibido, SecretKey llave) 
	{
		byte[] cipheredText;
		try
		{
			Cipher cipher = Cipher.getInstance(PADDING);

			byte[] clearText = msjRecibido;
			String s1 = new	String (clearText);
			System.out.println("clave original: " + s1);
			cipher.init(Cipher.ENCRYPT_MODE, llave);
			long startTime = System.nanoTime();
			cipheredText = cipher.doFinal(clearText);
			long endTime = System.nanoTime();
			String s2 = new	String (cipheredText);
			System.out.println("clave cifrada: " + s2);
			System.out.println("Tiempo: " + (endTime-startTime));
			return cipheredText;
		}
		catch(Exception e) 
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}


	/**
	 * Cifra mensaje infresado
	 * @param cipheredText byte[] con un texto cifrado
	 * @return s3 mensaje original
	 */
	public static String descifrar( byte[] cipheredText, SecretKey llave) 
	{
		try	
		{
			Cipher cipher = Cipher.getInstance(PADDING);
			cipher.init(Cipher.DECRYPT_MODE, llave);
			byte[] clearText = cipher.doFinal(cipheredText);
			String s3 = new String(clearText);
			return s3;
		}
		catch (Exception e)
		{
			System.out.println(	"Excepcion: " + e.getMessage());
			return null;
		}
	}

}
