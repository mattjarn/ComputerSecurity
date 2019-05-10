
package csec2019;

import java.math.BigInteger;

import java.security.KeyPairGeneratorSpi;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.InvalidKeySpecException;

/**
 * Class used by the JCE API.
 *
 * Do not use this class directly, instead use KeyPairGenerator.getInstance()
 * passing "RSA" and "CSec2019" as the algorithm and provider.
 */
public class CommutativeRSAKeyPairGenerator extends KeyPairGeneratorSpi {
    /**
     * Constructor.
     *
     * It does nothing. Most stuff is done in initialize and generateKeyPair.
     */
    public CommutativeRSAKeyPairGenerator() throws NoSuchAlgorithmException {}
    /**
     * Initialize this generator providing keysize, public exponent value, and
     * a secure source of randomness.
     *
     * Because the modulus must be the same for all generated key pairs, the
     * public exponent value must change. This initializer uses the provided
     * AlgorithmParamterSpec to determine the public exponent value of the
     * first generated key pair. Each subsequent call to generateKeyPair will
     * generate a key pair whose public value is the next greater prime than
     * thatof the last generated pair.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
        if (params instanceof RSAKeyGenParameterSpec) {
            RSAKeyGenParameterSpec rsa_params = (RSAKeyGenParameterSpec)params;
            initialize(rsa_params.getKeysize(), random);
            this.next_public = rsa_params.getPublicExponent();
            if (!this.next_public.isProbablePrime(90)) {
                throw new InvalidAlgorithmParameterException(
                    "Public exponent must be prime.");
            }
        } else {
            throw new InvalidAlgorithmParameterException(
                "RSA parameters required.");
        }
    }
    /**
     * Initialize this generator providing keysize and a secure source of
     * randomness.
     */
    public void initialize(int keysize, SecureRandom random) {
        this.keysize = keysize;
        this.random = random;

        // Divide the bits evenly between the two factors
        int p_size = keysize / 2;
        int q_size = keysize - p_size;
        BigInteger p = new BigInteger(p_size, 90, random);
        BigInteger q = new BigInteger(q_size, 90, random);

        // Store the modulus and its totient for later use
        m = p.multiply(q);
        System.out.printf("Keysize: %d\n", m.bitLength());
        BigInteger one = new BigInteger("1");
        tot_m = p.subtract(one).multiply(q.subtract(one));
    }
    /**
     * Generate an RSA key pair.
     *
     * Each key pair generated with this instance will be commutative with the
     * others generated by this instance.
     */
    public KeyPair generateKeyPair() throws ProviderException {
        // Construct the current keypair and prepare the next public exponent
        BigInteger e = next_public;
        BigInteger d = e.modInverse(this.tot_m);
        next_public = next_public.nextProbablePrime();
        try {
            return new KeyPair(
                kf.generatePublic(new RSAPublicKeySpec(m, d)),
                kf.generatePrivate(new RSAPrivateKeySpec(m, e))
            );
        } catch (InvalidKeySpecException ex) {
            throw new ProviderException("Provider malfunction", ex);
        }
    }

    private KeyFactory kf = KeyFactory.getInstance("RSA");
    private SecureRandom random;
    private int keysize;
    private BigInteger m;
    private BigInteger tot_m;
    private BigInteger next_public = new BigInteger("65537");
}
