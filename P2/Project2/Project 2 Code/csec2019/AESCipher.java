package csec2019;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipher extends CipherSpi 
{
    byte[] iv = new byte[16];
    boolean do_pad;
    boolean do_cbc;
    private AES cipher = null;
    private boolean decrypt = false;
    private int bufferAmount = 0;
    private byte[] buffer = new byte[16];
    private byte[] prev; // the previous block (used for CBC)


    protected void engineSetMode(String mode)
      throws NoSuchAlgorithmException 
    {
        if (mode.equals("CBC")) 
        {
            do_cbc = true;
        } 
        else if (mode.equals("ECB")) 
        {
            do_cbc = false;
        } 
        else 
        {
            throw new NoSuchAlgorithmException();
        }
    }
    protected void engineSetPadding(String padding)
      throws NoSuchPaddingException 
    {
        if (padding.equals("NoPadding")) 
        {
            do_pad = false;
        } 
        else if (padding.equals("PKCS5Padding")) 
        {
            do_pad = true;
        } 
        else 
        {
            throw new NoSuchPaddingException();
        }
    }
    protected int engineGetBlockSize() 
    {
        return 16; // This is constant for AES.
    }
    protected int engineGetOutputSize(int inputLen) 
    {
        /**
         * Implement me.
         */
        // should be the inputLen + whatever is in the buffer already + any padding that is necessary
        int outputSize = inputLen + bufferAmount;
        if(do_cbc)
        {
            if(decrypt || !do_pad)
            {
                return inputLen;
            }
            if(outputSize % 16 == 0)
            {
                outputSize += 16;
            }
            else
            {
                outputSize += 16 - inputLen % 16;
            }
        }
        return outputSize;
    }
    protected byte[] engineGetIV() 
    {
        byte[] retiv = new byte[16];
        System.arraycopy(iv, 0, retiv, 0, 16);
        return retiv;
    }
    protected AlgorithmParameters engineGetParameters() 
    {
        AlgorithmParameters ap = null;
        try 
        {
            ap = AlgorithmParameters.getInstance("AES");
            ap.init(new IvParameterSpec(engineGetIV()));
        } 
        catch (NoSuchAlgorithmException e) 
        {
            System.err.println("Internal Error: " + e);
        } 
        catch (InvalidParameterSpecException e) 
        {
            System.err.println("Internal Error: " + e);
        }
        return ap;
    }
    protected void engineInit(int opmode, Key key, SecureRandom random)
      throws InvalidKeyException 
    {
        try 
        {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        } 
        catch (InvalidAlgorithmParameterException e) 
        {
            System.err.println("Internal Error: " + e);
        }
    }
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
      throws InvalidKeyException 
    {
        try 
        {
            engineInit(opmode, key, params.getParameterSpec(IvParameterSpec.class), random);
        } 
        catch (InvalidParameterSpecException e) 
        {
            System.err.println("Internal Error: " + e);
        } 
        catch (InvalidAlgorithmParameterException e) 
        {
            System.err.println("Internal Error: " + e);
        }
    }
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException 
    {
        /**
         * Implement me.
         */
        prev = null;
        buffer = new byte[16];
        bufferAmount = 0;
        //check the key
        if (key == null || key.getEncoded() == null) 
        {
            throw new InvalidKeyException("No Secret Key provided");
        }
        if (key.getEncoded().length != 16 && key.getEncoded().length != 24 && key.getEncoded().length != 32) 
        {
            throw new InvalidKeyException("The key provided is not 128, 192, or 256 bits.");
        }
        //check the params
        if (params != null) 
        {
            if(!(params instanceof IvParameterSpec)) 
            {
                throw new InvalidAlgorithmParameterException("The parameters provided are not an instance of IvParameterSpec.");
            }
            else
            {
                byte[] iv_param = ((IvParameterSpec)params).getIV();
                if (iv_param == null || iv_param.length != 16) 
                {
                    throw new InvalidAlgorithmParameterException("The provided IV is invalid and must have a length of 16");
                }
            }
        }
        try 
        {
            cipher = new AES(key.getEncoded());
        } 
        catch (Exception e) 
        {
            System.err.println("Could not instantiate AES cipher: " + e);
            System.exit(-1);
        }
        decrypt = opmode == javax.crypto.Cipher.DECRYPT_MODE;

        if(do_cbc)
        { //the mode is CBC
            if(!decrypt) 
            { //using encryption
                if (params.equals(null)) 
                {
                    if(random == null)
                    {
                        throw new InvalidAlgorithmParameterException("A random source must be provided when no IV is specified");
                    }
                    random.nextBytes(iv); //generate an iv
                } 
                else 
                {
                    System.arraycopy(((IvParameterSpec)params).getIV(), 0, iv, 0, 16);
                }
            } 
            else 
            { //using decryption
                if (params.equals(null)) 
                {
                    throw new InvalidAlgorithmParameterException("In CBC decrypt mode, you must provide an IV");
                }
                System.arraycopy(((IvParameterSpec) params).getIV(), 0, iv, 0, 16);
            }
            prev = new byte[16];
            System.arraycopy(iv, 0, prev, 0, 16); //add the iv to the first block (CBC)
        }
        else 
        { //the mode is ECB
            if(!params.equals(null))
            {
                throw new InvalidAlgorithmParameterException("An IV cannot be specified in ECB mode");
            }
            iv = new byte[16];
        }
    }
    private int allocateSize(int inputLen) 
    {
        /**
         * Implement me.
         */
        int outputSize = engineGetOutputSize(inputLen);
        return outputSize > 0 ? outputSize : 1;
    }
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) 
    {
        byte[] output = new byte[allocateSize(inputLen)];
        int size = 0;
        try 
        {
            size = engineUpdate(input, inputOffset, inputLen, output, 0);
        } 
        catch (ShortBufferException e) 
        {
            System.err.println("Internal Error: " + e);
        }
        return Arrays.copyOf(output, size);
    }
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException 
    {
        /**
         * Implement me.
         * Continues a multiple-part encryption or decryption operation
         * (depending on how this cipher was initialized),
         * processing another data part.
         */
        if (engineGetOutputSize(inputLen) + outputOffset > output.length) 
        {
            throw new ShortBufferException("Output buffer size too small.");
        }
        int size = 0;
        while (inputLen + bufferAmount >= 16) 
        {
            System.arraycopy(input, inputOffset, buffer, bufferAmount, 16 - bufferAmount);
            size += doBlock(buffer, output, outputOffset);
            inputOffset += (16 - bufferAmount);
            inputLen -= (16 - bufferAmount);
            outputOffset += 16;
            bufferAmount = 0;
        }
        if (inputLen > 0) 
        {
            System.arraycopy(input, inputOffset, buffer, 0, inputLen);
            bufferAmount = inputLen;
        }
        return size;
    }
    private byte[] xor(byte[] B1, byte[] B2) 
    {
        byte[] xorResult = new byte[16];
        for (int i = 0; i < 16; i++) 
        {
            xorResult[i] = (byte)(Byte.toUnsignedInt(B1[i]) ^ Byte.toUnsignedInt(B2[i]));
        }
        return xorResult;
    }
    private int doBlock(byte[] block, byte[] output, int outputOffset) 
    {
        try 
        {
            if (!decrypt) 
            { //encrypting the block
                if (do_cbc) 
                { //CBC mode
                    block = xor(prev, block);
                    byte[] encrypted_block = cipher.encrypt(block);
                    System.arraycopy(encrypted_block, 0, prev, 0, 16); //this is now the previous block
                    System.arraycopy(encrypted_block, 0, output, outputOffset, 16); //add the encrypted block to the output
                } 
                else 
                { //ECB mode
                    System.arraycopy(cipher.encrypt(block), 0, output, outputOffset, 16); //add the encrypted block to the output
                }
            } 
            else 
            { //decrypting the block
                if (do_cbc) 
                { //CBC mode
                    byte[] temp = cipher.decrypt(block);
                    byte[] decrypted_block = xor(prev, temp);
                    System.arraycopy(decrypted_block, 0, output, outputOffset, 16); //add the decrypted block to the output
                    System.arraycopy(block, 0, prev, 0, 16); //replace the previous block
                } 
                else 
                { //ECB mode
                    System.arraycopy(cipher.decrypt(block), 0, output, outputOffset, 16); //add the decrypted block to the output
                }
            }
        } 
        catch (Exception e) 
        {
            System.err.println("Failed to encrypt/decrypt block: " + e);
            System.exit(-1);
        }
        return 16;
    }
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException 
    {
        try 
        {
            byte[] temp = new byte[engineGetOutputSize(inputLen)];
            int len = engineDoFinal(input, inputOffset, inputLen, temp, 0);
            return Arrays.copyOf(temp, len);
        } 
        catch (ShortBufferException e) 
        {
            System.err.println("Internal Error: " + e);
            return null;
        }
    }
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException 
    {
        /**
         * Implement me.
         */
        if (engineGetOutputSize(inputLen) + outputOffset > output.length) 
        {
            throw new ShortBufferException("Output buffer size is too small");
        }
        if (!do_pad && ((inputLen + bufferAmount) % 16 != 0)) 
        {
            throw new IllegalBlockSizeException("Must be a multiple of the block size if no padding is specified");
        }
        int size = 0;
        while (inputLen + bufferAmount >= 16) 
        {
            System.arraycopy(input, inputOffset, buffer, bufferAmount, 16 - bufferAmount);
            size += doBlock(buffer, output, outputOffset);
            inputOffset += (16 - bufferAmount);
            inputLen -= (16 - bufferAmount);
            outputOffset += 16;
            bufferAmount = 0;
        }
        if (inputLen > 0) 
        {
            System.arraycopy(input, inputOffset, buffer, 0, inputLen);
            bufferAmount = inputLen;
        }
        if (!decrypt) 
        { //encryption
            if (bufferAmount > 0) 
            { //if there's still some left in the buffer
                if(do_pad) 
                {
                    for (int i = bufferAmount; i < 16; i++) 
                    { //pad the buffer
                        buffer[i] = (byte) (16 - bufferAmount);
                    }
                }
                size += doBlock(buffer, output, outputOffset);
            } 
            else 
            {
                if(do_pad) 
                {
                    for (int i = 0; i < 16; i++) 
                    {
                        buffer[i] = 16;
                    }
                    size += doBlock(buffer, output, outputOffset);
                }
                //size += doBlock(buffer, output, outputOffset);
            }
        } 
        else 
        { //decryption
            System.arraycopy(output, outputOffset - 16, buffer, 0, 16);
            int depadAmount = 0;
            if (do_pad)
            {
                if (buffer[15] >= 1 && buffer[15] <= 16) 
                {
                    depadAmount = buffer[15];
                } 
                else 
                {
                    throw new BadPaddingException("Padding size is wrong");
                }
                for (int i = 16 - depadAmount; i < 16; i++) 
                {
                    if (buffer[i] != depadAmount) 
                    {
                        throw new BadPaddingException("Padding is corrupted");
                    }
                }
            }
            size -= depadAmount;
        }
        buffer = new byte[16];
        bufferAmount = 0;
        if (do_cbc) 
        {
            System.arraycopy(iv, 0, prev, 0, 16);
        }
        return size;

    }
}