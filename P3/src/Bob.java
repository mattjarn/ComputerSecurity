import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

import java.math.BigInteger;

import java.net.ServerSocket;
import java.net.Socket;

import java.nio.charset.Charset;

import java.security.*;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.*;

import javax.crypto.spec.SecretKeySpec;

/**
 * Implements side B of the Oblivious Transfer Protocol.
 */
public class Bob 
{
    /**
     * Default constructor.
     *
     * @param in an InputStream used to receive messages from Alice.
     * @param out an OutpuStream used to send messages to Alice.
     */
    public Bob(InputStream in, OutputStream out) 
    {
        this.in = new TLVInputStream(in);
        this.out = new TLVOutputStream(out);
    }

    /**
     * A default driver for those needing a quick-and-dirty test.
     *
     * This driver tries to connect to port 8023 . Once connected, the
     * OTP is executed once. The result is returned as the process exit code.
     * In the event Alice is caught cheating, the process exit code is -1.
     *
     * You will probably want to write a more capable driver for your own
     * testing.
     */
    public static void main(String[] args) 
    {
        Security.addProvider(new csec2019.CSec2019Prov());
/*        Security.addProvider(
            new org.bouncycastle.jce.provider.BouncyCastleProvider());*/
        int result = -10; // Some result code not used anywhere else
        System.err.print("Waiting for connection on port 8023: ");
        try 
        {
            Socket c = new Socket("localhost", 8023);
            System.err.println(" Connected.");

            Bob sideB = new Bob(c.getInputStream(), c.getOutputStream());
            result = sideB.execute();
        } 
        catch (OTPCheatException e) 
        {
            e.printStackTrace();
            System.err.println("\nCheating Detected: " + e);
            System.exit(-1);
        } 
        catch (java.io.IOException e) 
        {
            e.printStackTrace();
            System.err.println("\nError opening socket: " + e);
            System.exit(-2);
        } 
        catch (OTPException e) 
        {
            e.printStackTrace();
            System.err.println("\nError executing OTP: " + e);
            System.exit(-3);
        } 
        catch (TLVException e) 
        {
            e.printStackTrace();
            System.err.println("\nCommunication error executing OTP: " + e);
            System.err.println("This typically occurs when Bob disconnects," +
                               " crashes, or sends a message out of order.");
            System.exit(-4);
        }
        switch (result) {
            case Outcome.LOSE: 
            {
                System.out.println("I Lose");
            } break;
            case Outcome.WIN: 
            {
                System.out.println("I Win");
            } break;
            default: 
            {
                // This should never happen
                System.err.println("Internal Error");
            }
        }
        System.exit(result);
    }

    /**
     * Execute side B of the Oblivious Transfer Protocol.
     *
     * Executes the OTP using the provided communication channels.
     * @return the outcome of the OTP: Outcome.WIN or Outcome.LOSE.
     */
    int execute() throws OTPException 
    {
        // Instantiate a charmap for encoding strings later
        Charset utf8 = Charset.forName("UTF-8");
        // Step 1: Only A, A generates 2 Asym key pairs and message M
        // Step 2: Create Symm key
        System.err.println(2);
        KeyGenerator keyGenerator = null;

        try 
        {
            keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
        } 
        catch (NoSuchAlgorithmException e) 
        {
            throw new OTPException("AES generator not available",
                    e);
        } 
        catch (InvalidParameterException e) 
        {
            throw new OTPException("Cannot generate appropriately-sized keys",
                    e);
        }

        SecretKey K_B = keyGenerator.generateKey();

        // Step 3: 
        //Must write how bob receives the keys
        byte[] K_I_Pub_Bytes = null;
        byte[] K_J_Pub_Bytes = null;


        System.err.println(3);
        try 
        {
            K_I_Pub_Bytes = in.get(0x30); //X.509 Encoding
            K_J_Pub_Bytes = in.get(0x31); //X.509 Encoding
        } 
        catch (IOException e) 
        {
            throw new OTPException("Unable to receive public keys", e);
        }

        RSAPublicKey K_I_Pub = null;
        RSAPublicKey K_J_Pub = null;

        try 
        {
            K_I_Pub = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(K_I_Pub_Bytes));
            K_J_Pub = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(K_J_Pub_Bytes));
            if(K_I_Pub.equals(K_J_Pub)){
            	throw new OTPCheatException("Both public keys are the same");
        }
            
            if(!K_I_Pub.getModulus().equals(K_J_Pub.getModulus()))
            {
            	throw new OTPCheatException("Keys are not commutative");
            }
            
            
        } 
        catch (NoSuchAlgorithmException e) 
        {
            throw new OTPException("Commutative RSA generator not available",
                    e);
        } 
        catch (InvalidParameterException e) 
        {
            throw new OTPException("Cannot generate appropriately-sized keys",
                    e);
        } 
        catch (InvalidKeySpecException e) 
        {
            throw new OTPException("Cannot generate appropriately-sized keys",
                    e);
        }

        // Step 4: Select H from I:J at random and sends Kb locked with kH
        System.err.println(4);
        byte[] K_B_H_data = null;
        RSAPublicKey K_H = null;
        byte H = (byte)(new BigInteger(1, random).intValue());
        K_H = H == 0 ? K_I_Pub : K_J_Pub;
        byte[] K_H_B = null;

        try
        {
            K_H_B = Common.encryptKey(K_H, K_B, random);

        } 
        catch (NoSuchAlgorithmException e) 
        {
            throw new OTPException("Commutative RSA generator not available",
                    e);
        } 
        catch (InvalidKeyException e) 
        {
            throw new OTPException("Cannot generate appropriately-sized keys",
                    e);
        } 
        catch (IllegalBlockSizeException e) 
        {
            throw new OTPException("Cannot generate appropriately-sized keys",
                    e);
        } 
        catch (BadPaddingException e) 
        {
            throw new OTPException("Cannot generate appropriately-sized keys",
                    e);
        } 
        catch (NoSuchPaddingException e) 
        {
            throw new OTPException("Cannot generate appropriately-sized keys",
                    e);
        }

        try 
        {
            out.put(0x40, K_H_B);
        } 
        catch (IOException e) 
        {
            throw new OTPException("Unable to send encrypted key", e);
        }
        //Step 5 Only A, A Computes G = I ,J at random
        // Step 6: Receive the encrypted message.
        System.err.println(6);
        String Mprime = null;
        Cipher K_B_cipher = null;
        byte[] M = null;
        try 
        {   K_B_cipher = Cipher.getInstance("AES/ECB/NoPadding");
            K_B_cipher.init(Cipher.DECRYPT_MODE, K_B);
            M = K_B_cipher.doFinal(in.get(0x60));
            Mprime = new String(M);
            System.out.println(Mprime);   
        } 
        catch (NoSuchAlgorithmException e) 
        {
            throw new OTPException("AES not available", e);
        } 
        catch (NoSuchPaddingException e) 
        {
            throw new OTPException("NoPadding not available for AES", e);
        } 
        catch (InvalidKeyException e) 
        {
            throw new OTPCheatException("Bob provided an invalid AES key", e);
        } 
        catch (IllegalBlockSizeException e) 
        {
            throw new OTPException("Message must be 16*n bytes in length", e);
        } 
        catch (BadPaddingException e) 
        {
            // Should not be an issue in encrypt mode
            throw new OTPException("Internal error", e);
        } 
        catch (IOException e) 
        {
            throw new OTPException("Unable to send encrypted message", e);
        }

        byte G[];
        try 
        {
            //out.putByte(0x61, G);
            
            G = in.get(0x61);
           
        } 
        catch (IOException e) 
        {
            throw new OTPException("Unable to receive coin flip result", e);
        }
        // Step 7: Send the decrypted message and H (what did Bob call?)
        System.err.println(7);
        try
        {
            out.put(0x70, M);
        } 
        catch (IOException e) 
        {
            throw new OTPException("Unable to send decrypted message", e);
        }
        try 
        {
            out.putByte(0x71, H);
        } 
        catch (IOException e) 
        {
            throw new OTPException("Unable to receive Bob's call", e);
        }
        // Step 8: Receive the private keys
        System.err.println(8);
        byte[] K_I_Priv_Bytes = null;
        byte[] K_J_priv_Bytes = null;

        try
        {
            K_I_Priv_Bytes = in.get(0x80); //PKCS8 Encoding
            K_J_priv_Bytes = in.get(0x81); //PKCS8 Encoding
        }
        catch (IOException e)
        {
            throw new OTPException("Unable to receive public keys", e);
        }

        RSAPrivateKey K_I_Priv = null;
        RSAPrivateKey K_J_Priv = null;

        try 
        {
            K_I_Priv = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(K_I_Priv_Bytes));
            K_J_Priv = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(K_J_priv_Bytes));
            if(K_I_Priv.equals(K_J_Priv))
            {
            	throw new OTPCheatException("Both private keys are the same");
            }

            if(!K_I_Priv.getModulus().equals(K_J_Priv.getModulus()))
            {
            	throw new OTPCheatException("KI keys are not commutative");
            }
            
        } 
        catch (NoSuchAlgorithmException e) 
        {
            throw new OTPException("Commutative RSA generator not available",
                    e);
        } 
        catch (InvalidParameterException e) 
        {
            throw new OTPException("Cannot generate appropriately-sized keys",
                    e);
        }
        catch (InvalidKeySpecException e) 
        {
            throw new OTPException("Cannot generate appropriately-sized keys",
                    e);
        }
        Cipher EncryptKI = null;
        Cipher DecryptKI = null;
        Cipher EncryptKJ = null;
        Cipher DecryptKJ = null;
        try
        {
        	EncryptKI =  Cipher.getInstance("RSA/ECB/NoPadding");
        	EncryptKI.init(Cipher.ENCRYPT_MODE, K_I_Pub);
        	byte [] Encipher = null;
        	Encipher =  EncryptKI.doFinal(Msg.getBytes(utf8));
        	DecryptKI = Cipher.getInstance("RSA/ECB/NoPadding");
        	DecryptKI.init(Cipher.DECRYPT_MODE, K_I_Priv);
        	byte [] Decipher = null;
        	Decipher = DecryptKI.doFinal(Encipher);
        	String Text = new String(Decipher);
        	Text = Text.trim();
        	System.out.println(Text);
        	System.out.println(Msg);
        	
        	if(!Text.equals(Msg))
        	{
        		throw new OTPCheatException("Key pairs do not match!");
        	}
        	
        	EncryptKJ =  Cipher.getInstance("RSA/ECB/NoPadding");
        	EncryptKJ.init(Cipher.ENCRYPT_MODE, K_J_Pub);
        	Encipher = null;
        	Encipher =  EncryptKJ.doFinal(Msg1.getBytes(utf8));
        	DecryptKJ = Cipher.getInstance("RSA/ECB/NoPadding");
        	DecryptKJ.init(Cipher.DECRYPT_MODE, K_J_Priv);
        	Decipher = null;
        	Decipher = DecryptKJ.doFinal(Encipher);
        	Text = new String(Decipher);
        	Text = Text.trim();
        	System.out.println(Text);
        	System.out.println(Msg1);
        	if(!Text.equals(Msg1))
        	{
        		throw new OTPCheatException("Key pairs do not match!");
        	}

        }
        catch (NoSuchAlgorithmException e) 
        {
            throw new OTPException("AES not available", e);
        } 
        catch (NoSuchPaddingException e) 
        {
            throw new OTPException("NoPadding not available for AES", e);
        } 
        catch (InvalidKeyException e) 
        {
            throw new OTPCheatException("Bob provided an invalid AES key", e);
        } 
        catch (IllegalBlockSizeException e) 
        {
            throw new OTPException("Message must be 16*n bytes in length", e);
        } 
        catch (BadPaddingException e) 
        {
            // Should not be an issue in encrypt mode
            throw new OTPException("Internal error", e);
        } 
        
        // Interpret the result
        if (G[0] == H)
        {
        	return Outcome.WIN;
        } 
        else 
        {
           return Outcome.LOSE;
        }
    }
    private String Msg1 = "I am the victor"; //length must be a multiple of 16
    private String Msg = "I am the winner"; //length must be a multiple of 16
    private TLVInputStream in;
    private TLVOutputStream out;
    private SecureRandom random = new SecureRandom();
}
