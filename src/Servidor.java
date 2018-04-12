import java.io.IOException;
import java.net.ServerSocket;

public class Servidor 
{
	private static int PUERTO=2000;
	
	public static void main(String[] args) throws IOException 
	{
		 ServerSocket ss = null;
		 boolean continuar = true;
		 int i =0;
		 try 
		 {
			 ss = new ServerSocket(PUERTO);
		 } 
		 catch (IOException e)
		 {			 
			 System.err.println("No pudo crear socket en el puerto: " + 2000);
			 System.exit(-1);
		 }

		 while (continuar)
		 {

			 //new ThreadServidor(ss.accept(),i).start();

			 // incremente identificador de thread
			 i++;
		 }
		 ss.close();
	}
}
