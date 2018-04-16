//David Felipe Niño Romero		201412734 
//Nicolás Mateo Hernández Rojas 		 201412420

package UnidadDeDistribución;

import java.security.Key;
import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class CalculadorDigestHmacMD5
{
	
	public CalculadorDigestHmacMD5() 
	{
		//Constructor vacío.
	}

	private byte[] getKeyedDigest(byte[] buffer) 
	{
		try 
		{
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			md5.update(buffer);
			return md5.digest();
		} 
		catch (Exception e) 
		{
			return null;
		}
	}

	public byte[] calcular(String dato, SecretKey key)
	{
		try
		{
			Mac mac = Mac.getInstance("HMACMD5");
			mac.init(key);
			
			byte[] text = dato.getBytes();
			String s1 = new String(text);
			System.out.println("dato original: " + s1);
			byte [] digest = mac.doFinal(text);
			String s2 = new String(digest);
			System.out.println("digest: "+ s2);
			return digest;
		}
		catch (Exception e)
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}
	
    public boolean sonIguales(String msj, byte[] digest, SecretKey llave) 
    {
        boolean son= true;
        byte[] mensaje = calcular(msj, llave);
        if (digest.length == mensaje.length)
        {
            for (int i=0; i<mensaje.length && son;i++)
            {
                if (digest[i]!=mensaje[i])
                {
                    son = false;
                }
            }
        }
        else
        {
            son = false;
        }
        
        return son;
    }


}
