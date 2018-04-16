//David Felipe Niño Romero		201412734 
//Nicolás Mateo Hernández Rojas 		 201412420


package UnidadDeDistribución;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.util.encoders.Base64;


public class ClienteSeguro 
{

	private static final int PUERTO = 8081;
	private static final String DIR = "localhost";
	private static final String algoritmoSimetrico = "AES";
	private static final String algoritmoAsimetrico = "RSA";
	private static final String algoritmoDigest = "HMACMD5";
	
	private Socket s;
	private PrintWriter out;
	private BufferedReader in;
	
	private PublicKey llaveServidor;
	private KeyPair llaveCliente;
	private SecretKey llaveSesion;
	
	//-------------------------
	private ManejadorCertificado mc;
	private KeyPair keyAsin;
	private CifradorAsimetricoRSA cifradorAsim;
	private CifradorSimetricoAES cifradorSim;
	private CalculadorDigestHmacMD5 cmd;	
	
	public ClienteSeguro()
	{
		try
		{
			cifradorAsim = new CifradorAsimetricoRSA();
			keyAsin = cifradorAsim.darLlave();

			conectar();
			conversar();
		} 
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}

	public void conectar() throws Exception
	{
			s = new Socket(DIR, PUERTO);
			out = new PrintWriter(s.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(s.getInputStream()));
	}

	public void conversar() throws Exception
	{
		//Etapa 1 Inicio de sesion
		
		inicioSesion();
		
		//Etapa 2 Intercambio de CD
		
		intercambioCD();		
		
		//Etapa 3 Autenticación
		
		recibirLlaveSesion();		
		
		//Etapa 4 Reporte y manejo de actualización
		
		reporteAct();	
		
		System.out.println("¡Se termino!");
	}


	private void inicioSesion() throws Exception 
	{
		out.println("HOLA");
		String rta = in.readLine();
		if(!rta.equals("INICIO"))
		{
			throw new Exception("Respuesta inesperada. Etapa 1.");
		}
		out.println("ALGORITMOS:"+algoritmoSimetrico+":"+algoritmoAsimetrico+":"+algoritmoDigest);
		rta = in.readLine();		
		if ((!rta.contains(":")) || (!rta.split(":")[0].equals("ESTADO")))
		{
	        throw new Exception("Formato de mensaje inesperado.");
	    }
		rta = rta.split(":")[1];
		if (!rta.equals("OK"))
		{
	        throw new Exception("Algoritmos no soportados.");
	    }
	}

	private void intercambioCD() throws IOException
	{
		llaveServidor = ManejadorCertificado.creationYProcesamiento(keyAsin,s.getOutputStream(), s.getInputStream(), out, in);
	}

	private void recibirLlaveSesion() throws Exception
	{
		String rta = in.readLine();		
		if ((!rta.contains(":")) || (!rta.split(":")[0].equals("INICIO")))
		{
	        throw new Exception("Formato de mensaje inesperado.");
	    }
		rta = rta.split(":")[1];
		byte[] bytesCifrados = toByteArray(rta);
		byte[] bytes = cifradorAsim.descifrar(bytesCifrados);
		llaveSesion = new SecretKeySpec(bytes, "AES");
		cmd = new CalculadorDigestHmacMD5();
	}
	
	private void reporteAct() throws Exception
	{	
		System.out.println("Ingrese la posición:");
		
		//En este instante debe ingresarse la posición nueva (en formato correcto) EN LA CONSOLA para actualizarla.
		
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));		
		String pos = stdIn.readLine();
		
		//Se controla que se ingrese un formato de posición correcto (AA BB, CC DD)
		if(pos.split(",").length == 2)
		{			
			String pos1 = pos.split(",")[0];
			String pos2 = pos.split(",")[1];
						
			if(pos1.trim().split(" ").length != 2 || pos2.trim().split(" ").length != 2)
			{
				throw new Exception("Formato de posición incorrecto.");		
			}
		}
		else
		{
			throw new Exception("Formato de posición incorrecto.");	
		}
		
		//ACT1
		
		byte[] posCifradaSim = CifradorSimetricoAES.cifrar(pos, llaveSesion);
		String posEnviar = "ACT1:"+toHexString(posCifradaSim);
		System.out.println(posEnviar);
		out.println(posEnviar);
		
		//ACT2
		byte[] consultaHash = cmd.calcular(pos, llaveSesion);
		byte[] consultaHashCifrada = CifradorAsimetricoRSA.cifrar(llaveServidor, consultaHash);
		String posHashEnviar = "ACT2:"+toHexString(consultaHashCifrada);
		System.out.println(posHashEnviar);
		out.println(posHashEnviar);
		
		//Recibir confirmación
		String rta = in.readLine();		
		if ((!rta.contains(":")) || (!rta.split(":")[0].equals("ESTADO")))
		{
	        throw new Exception("Formato de mensaje inesperado.");
	    }
		rta = rta.split(":")[1];
		if (!rta.equals("OK"))
		{
	        throw new Exception("Error en actualización y reporte.");
	    }		
	}
		
	//------ Metodos Auxiliares
	
	/**
	 * Recibe un array de bytes y lo convierte en hexadecimal (es para enviar datos)
	 * @param array de bytes
	 * @return hexa
	 */
	public static String toHexString(byte[] array) 
	{
	    return DatatypeConverter.printHexBinary(array);
	}
	
	/**
	 * Recibe un string en hexa y lo convierte a arreglo de bytes (es para recibir datos)
	 * @param s hexa
	 * @return bytes
	 */
	public static byte[] toByteArray(String s) 
	{
	    return DatatypeConverter.parseHexBinary(s);
	}	
	
	//------ Main
	public static void main(String[] args) 
	{
		ClienteSeguro ci = new ClienteSeguro();
	}
}
