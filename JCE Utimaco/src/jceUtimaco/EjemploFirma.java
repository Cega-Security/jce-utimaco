package jceUtimaco;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import CryptoServerJCE.CryptoServerProvider;

public class EjemploFirma {

	public static void main(String[] args) throws Exception {
		CryptoServerProvider provider = null;
	    
	    try
	    {
	    	// Cargar provider    
	    	provider = new CryptoServerProvider("3001@127.0.0.1", 5000);
	    	
	    	//Opcion 1 para cargar directo del archivo que esta en la linea del provider java.security
	    	//cryptoServerProvider = (CryptoServerProvider)Security.getProvider("CryptoServer"); 
	    	
	    	//Opcion 2 para indicar la ruta del archivo de config si no se puso en java.security
	    	//provider = new CryptoServerProvider("CryptoServer.cfg"); 
	    	
	    	//Opcion 3 para configurar el provider directo en codigo se usa provider.setProperty
	        provider.setProperty("KeepSessionAlive", "0");
	        provider.setProperty("KeyGroup", "group");
	        provider.setProperty("KeySpecifier", "-1"); 
	        System.out.println("Device  : " + provider.getCryptoServer().getDevice());
	        System.out.println("Device  : " + provider.getCryptoServer().getVersion());
	      
	        // authenticate
	        Security.addProvider(provider);
	        provider.loginPassword("user", "pass");
	        String keyName= "key_RSA"; 
	        System.out.println("User logged in");
	      
	     
	        // for all modes
		    Algorithm mode= new Algorithm("SHA256withRSA", null);
		    String algo = mode.algo;
		    System.out.println("algo: " + algo);
	          
	        System.out.println("  Sign on  : " + provider.getName());
	        System.out.println("  Verify on: " + provider.getName());               
	               
	        // open key store                                                            
	        KeyStore ks = KeyStore.getInstance("CryptoServer", provider);       
	        ks.load(null, null);    
	        System.out.println("KeyStore: " + ks.getType() + "\n");
	        Key entry = ks.getKey(keyName, null);
	        System.out.println(entry.getAlgorithm());
	        // list keys    
	      
	        // do test        
	        Signature sig = Signature.getInstance(algo, provider);
	        
	        String nameToSign;
	        nameToSign = "Cega Security";
	        System.out.println("Texto a firmar: "+ nameToSign);
	          
	        byte [] data1=nameToSign.getBytes(StandardCharsets.UTF_8);
	        // sign
	        sig.initSign((PrivateKey) entry);              
	        if (mode.param != null)
	          sig.setParameter(mode.param);             
	        sig.update(data1);
	              
	        byte [] sign = sig.sign();
	        
	        String firmaCompleta;
	        Base64.Encoder encoder= Base64.getEncoder();
	        firmaCompleta= encoder.encodeToString(sign);
	        System.out.println("La firma es: "+firmaCompleta);
	        
	        Base64.Decoder decoder= Base64.getDecoder();
	        byte[] firmaCompletaDec=decoder.decode(firmaCompleta);
	        System.out.println("Decodificado: "+firmaCompletaDec);
	          

	        Certificate cert = ks.getCertificate(keyName);
	        System.out.println("cert: "+cert);
	        
	      }
	    catch (Exception ex)
	    {
	      throw ex;
	    }
	    finally
	    {
	      // logoff
	      if (provider != null)
	        provider.logoff();
	    }
	    
	    System.out.println("Done");

	}
	
	private static class Algorithm
	  {
	    String algo;
	    AlgorithmParameterSpec param;
	    
	    public Algorithm(String algo, AlgorithmParameterSpec param)
	    {
	      this.algo = algo;
	      this.param = param;
	    }
	  }
	  
	  private static byte [] getRandom(int length)
	  {       
	    try
	    {
	      byte[] buf = new byte[length];      
	      SecureRandom rng = SecureRandom.getInstance("SHA256PRNG");
	      
	      do
	      {
	        rng.nextBytes(buf);
	      }
	      while (buf[0] == 0);
	      
	      return buf;
	    }
	    catch (Exception ex)
	    {
	      return null;
	    }    
	  }
	  
	  private static byte [] cat(byte [] a)
	  {

	    byte [] res = new byte[a.length];
	    System.arraycopy(a,0,res,0,a.length);

	    return(res);
	  }

}
