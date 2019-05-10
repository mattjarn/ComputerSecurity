import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;
import java.util.Scanner;

public class Chat 
{
    public static void main(String[] args) 
    {
        parseArgs(new ArrayDeque<String>(Arrays.asList(args)));
        Socket c = null;
        java.security.Security.insertProviderAt(new csec2019.CSec2019Prov(), 1);
        ChatCipher cipher = null;
        if (mode == SERVER) 
        {
            try 
            {
                ServerSocket s = new ServerSocket(port);
                c = s.accept();
                cipher = DHServerSide(c.getInputStream(), c.getOutputStream());
            } 
            catch (IOException e) 
            {
                System.err.println("There was an error opening the server:");
                System.err.println(e);
                System.exit(-3);
            } 
            catch (SecurityException e) 
            {
                System.err.println("You are not allowed to open the server:");
                System.err.println(e);
                System.exit(-2);
            }
        } 
        else if (mode == CLIENT) 
        {
            try 
            {
                c = new Socket(addr, port);
                cipher = DHClientSide(c.getInputStream(), c.getOutputStream());
            } 
            catch (IOException e) 
            {
                System.err.println("There was an error connecting:");
                System.err.println(e);
                System.exit(-3);
            } 
            catch (SecurityException e) 
            {
                System.err.println("You are not allowed to connect:");
                System.err.println(e);
                System.exit(-2);
            }
        } 
        else 
        {
            System.err.println("Please specify the mode.");
            printUsage();
            System.exit(-1);
        }
        try 
        {
            new Thread(new ChatSender(System.in, c.getOutputStream(), cipher.getEncryption())).start();
            new Thread(new ChatReceiver(c.getInputStream(), System.out, cipher.getDecryption())).start();
        } 
        catch (IOException e) 
        {
            System.err.println("There was an error setting up data transfer:");
            System.err.println(e);
            System.exit(-3);
        } 
        catch (NullPointerException e) 
        {
            System.err.println("The Cipher failed to initialize: ");
            System.err.println(e);
            System.exit(-1);
        }
    }
    private static void parseArgs(Queue<String> args) 
    {
        while (args.peek() != null) 
        {
            String opt = args.poll();
            if (opt.equals("-s")) {
                if (mode != UNSPECIFIED) 
                {
                    printUsage();
                    System.exit(-1);
                }
                mode = SERVER;
                parsePort(args);
            } 
            else if (opt.equals("-c")) 
            {
                if (mode != UNSPECIFIED) 
                {
                    printUsage();
                    System.exit(-1);
                }
                mode = CLIENT;
                parseAddr(args);
                parsePort(args);
            }
        }
    }
    private static void badPort() 
    {
        System.err.println("Please specify a port between 1 and 65535.");
        printUsage();
        System.exit(-1);
    }
    private static void parsePort(Queue<String> args) 
    {
        String strPort = args.poll();
        if (strPort == null) 
        {
            badPort();
        }
        try 
        {
            port = Integer.parseInt(strPort);
        } 
        catch (NumberFormatException e) 
        {
            badPort();
        }
        if (!(1 <= port && port <= 65535)) 
        {
            badPort();
        }
    }
    private static void badAddr() 
    {
        System.err.println("Please specify an IP address or host name.");
        printUsage();
        System.exit(-1);
    }
    private static void parseAddr(Queue<String> args) 
    {
        String hostname = args.poll();
        if (hostname == null) 
        {
            badAddr();
        }
        try 
        {
            addr = InetAddress.getByName(hostname);
        } 
        catch (UnknownHostException e) 
        {
            System.err.println("The address '" + hostname + "' is unrecognized or could not be resolved.");
            badAddr();
        } 
        catch (SecurityException e) 
        {
            System.err.println("You are not allowed to resolve '" + hostname + "'.");
            System.exit(-2);
        }
    }
    private static void printUsage() 
    {
        System.err.println("Usage:");
        System.err.println("    java Chat -s PORT");
        System.err.println("    invokes Chat in server mode attempting to listen on PORT.");
        System.err.println("");
        System.err.println("    java Chat -c ADDRESS PORT");
        System.err.println("    invokes Chat in client mode attempting to connect to ADDRESS on PORT.");
    }

    private static byte[] read(InputStream in, byte[] input) throws IOException 
    {
        int len = in.read(input);
        byte[] output = new byte[len];
        System.arraycopy(input, 0, output, 0, len);
        return output;
    }

    private static ChatCipher DHServerSide(InputStream in, OutputStream out)
    {
        System.err.println("Starting Server Side DiffieHellman");
        byte[] b = new byte[1024];
        ChatCipher cipher = null;
        try 
        {
            System.err.println("Generating a set of algorithm parameters");
            AlgorithmParameterGenerator APG = AlgorithmParameterGenerator.getInstance("DH");
            System.err.println("Initializing parameters with a size of 1024");
            APG.init(1024);
            AlgorithmParameters params = APG.generateParameters();
            System.err.println("Generated parameters");
            System.err.println("Sending Encoded Algorithm Parameters to the client");
            out.write(params.getEncoded());
            System.err.println("Generating key pair");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(params.getParameterSpec(DHParameterSpec.class));
            KeyPair keys = kpg.generateKeyPair();
            System.err.println("Sending public key to client");
            out.write(keys.getPublic().getEncoded());
            System.err.println("Receiving client's public key");
            byte[] key = read(in, b);
            KeyFactory kf = KeyFactory.getInstance("DH");
            System.err.println("Decode client's public key");
            PublicKey otherHalf = kf.generatePublic(new X509EncodedKeySpec(key));
            System.err.println("Creating KeyAgreement");
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(keys.getPrivate());
            System.err.println("Generating shared secret");
            ka.doPhase(otherHalf, true);
            byte[] secret = ka.generateSecret();
            byte[] secretKeyBytes = new byte[16];
            System.arraycopy(secret, 0, secretKeyBytes, 0, 16);
            SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES");
            System.err.println("Receiving shared IV from Client");
            byte[] iv = read(in, b);
            cipher = cipher.init(secretKey, iv);
            System.err.println("Exchange is complete, you may begin chatting now");
        } 
        catch(NoSuchAlgorithmException e)
        {
            System.err.println("Algorithm does not exist: " + e);
        } 
        catch(ProviderException e)
        {
            System.err.println("No such provider: " + e);
        } 
        catch(IOException e)
        {
            System.err.println("IO exception occurred: " + e);
        } 
        catch(InvalidParameterSpecException e)
        {
            System.err.println("Invalid parameters specified: " + e);
        } 
        catch(InvalidAlgorithmParameterException e) 
        {
            System.err.println("Invalid Algorithm Parameters specified: " + e);
        } 
        catch(InvalidKeySpecException e) 
        {
            System.err.println("Invalid key spec exception occurred: " + e);
        } 
        catch(InvalidKeyException e)
        {
            System.err.println("An invalid key was used: " + e);
        } 
        catch (NoSuchPaddingException e) 
        {
            System.err.println("Padding scheme not supported: " + e);
        } 
        catch (NoSuchProviderException e) 
        {
            System.err.println("No such provider:" + e);
        }
        return cipher;
    }

    private static ChatCipher DHClientSide(InputStream in, OutputStream out)
    {
        System.err.println("Starting Client Side DiffieHellman");
        byte[] b = new byte[1024];
        ChatCipher cipher = null;
        try 
        {
            AlgorithmParameters params = AlgorithmParameters.getInstance("DH");
            System.err.println("Receiving Algorithm Parameters");
            byte[] encodedParams = read(in, b);
            System.err.println("Decoding Algorithm Parameters");
            params.init(encodedParams);
            System.err.println("Generating key pair");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(params.getParameterSpec(DHParameterSpec.class));
            KeyPair keys = kpg.generateKeyPair();
            System.err.println("Sending public key to server");
            out.write(keys.getPublic().getEncoded());
            System.err.println("Receiving server's public key");
            byte[] key = read(in, b);
            KeyFactory kf = KeyFactory.getInstance("DH");
            System.err.println("Decoding server's public key");
            PublicKey otherHalf = kf.generatePublic(new X509EncodedKeySpec(key));
            System.err.println("Creating KeyAgreement");
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(keys.getPrivate());
            System.out.println("Generating shared secret");
            ka.doPhase(otherHalf, true);
            byte[] secret = ka.generateSecret();
            byte[] secretKeyBytes = new byte[16];
            System.arraycopy(secret, 0, secretKeyBytes, 0, 16);
            SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES");
            System.out.println("Generating shared IV");
            byte[] iv = secretKey.getEncoded();
            System.out.println("Sending shared IV to Server");
            out.write(iv);
            cipher = cipher.init(secretKey, iv);
            System.err.println("Exchange is complete, you may begin chatting now");
        } 
        catch(NoSuchAlgorithmException e)
        {
            System.err.println("Algorithm does not exist: " + e);
        } 
        catch(ProviderException e)
        {
            System.err.println("No such provider: " + e);
        } 
        catch(IOException e)
        {
            System.err.println("IO exception occurred: " + e);
        } 
        catch(InvalidParameterSpecException e)
        {
            System.err.println("Invalid parameters specified: " + e);
        } 
        catch(InvalidAlgorithmParameterException e) 
        {
            System.err.println("Invalid Algorithm Parameters specified: " + e);
        } 
        catch(InvalidKeySpecException e) 
        {
            System.err.println("Invalid key spec exception occurred: " + e);
        } 
        catch(InvalidKeyException e)
        {
            System.err.println("An invalid key was used: " + e);
        } 
        catch (NoSuchPaddingException e) 
        {
            System.err.println("Padding scheme not supported: " + e);
        } 
        catch (NoSuchProviderException e) 
        {
            System.err.println("No such provider:" + e);
        }
        return cipher;
    }

    private static final byte UNSPECIFIED = 0;
    private static final byte SERVER = 1;
    private static final byte CLIENT = 2;

    private static byte mode = UNSPECIFIED;
    private static InetAddress addr = null;
    private static int port = 0;
}
// only call engineDoFinal()?
class ChatSender implements Runnable 
{
    public ChatSender(InputStream screen, OutputStream conn, Cipher cipher) 
    {
        this.screen = new Scanner(screen);
        this.conn = new PrintStream(conn);
        this.cipher = cipher;
    }
    public void run() 
    {
        while(true) 
        {
            try 
            {
                String line = screen.nextLine();
                byte[] input = line.getBytes();
                byte[] output = new byte[cipher.getOutputSize(input.length)];
                output = cipher.doFinal(input);
                conn.write(output, 0, output.length);
            } 
            catch (IllegalBlockSizeException e) 
            {
                System.err.println("Block size exception occurred: " + e);
            } 
            catch (BadPaddingException e) 
            {
                System.err.println("Padding exception occurred: " + e);
            }
        }
    }
    private Scanner screen;
    private PrintStream conn;
    private Cipher cipher;
}

class ChatReceiver implements Runnable 
{
    public ChatReceiver(InputStream conn, OutputStream screen, Cipher cipher) 
    {
        this.conn = conn;
        this.screen = screen;
        this.cipher = cipher;
    }
    public void run() 
    {
        byte[] b = new byte[1024];

        while (true) 
        {
            try 
            {
                int len = conn.read(b);
                if (len == -1) break;
                byte[] input = new byte[len];
                System.arraycopy(b, 0, input, 0, len);
                byte[] output = new byte[cipher.getOutputSize(len)];
                output = cipher.doFinal(b, 0, len);
                screen.write(output, 0, output.length);
                System.out.print("\n");
                screen.flush();
            } 
            catch (IOException e) 
            {
                System.err.println("There was an error receiving data: " + e);
            } 
            catch (IllegalBlockSizeException e) 
            {
                System.err.println("Block size exception occurred: " + e);
            } 
            catch (BadPaddingException e) 
            {
                System.err.println("Padding exception occurred: " + e);
            }
        }
    }
    private InputStream conn;
    private OutputStream screen;
    private Cipher cipher;
}

class ChatCipher {
    public ChatCipher(Cipher e, Cipher d) 
    {
        this.encryption = e;
        this.decryption = d;
    }
    public static ChatCipher init(SecretKey key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException 
    {
        Cipher encryption = Cipher.getInstance("AES/CBC/PKCS5Padding");
        Cipher decryption = Cipher.getInstance("AES/CBC/PKCS5Padding");
        //System.err.println("Provider being used is " + encryption.getProvider() + " for encryption");
        //System.err.println("Provider being used is " + decryption.getProvider() + " for decryption");
        SecureRandom random = new SecureRandom();
        encryption.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv), random);
        decryption.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv), random);
        return new ChatCipher(encryption, decryption);
    }

    public Cipher getEncryption() 
    {
        return this.encryption;
    }
    public Cipher getDecryption() 
    {
        return this.decryption;
    }

    private Cipher encryption;
    private Cipher decryption;
}