
public class KeyGenerator {

    private static final int exponent = 3;
    private int base;
    private int modulus;
    private int simpleKey;
    private static final int public_key = 8736;
    private static final int private_key = 3782;

    public int getKey() {
        return (int) Math.pow(base, exponent) % modulus;
    }

    public int getKeyBase(int base) {
        return (int) Math.pow(base, exponent) % modulus;
    }

    public int getPublicKey() {
        return public_key;
    }

    public int getPrivateKey() {
        return private_key;
    }

    public void setSimpleKey(int simpleKey) {
        this.simpleKey = simpleKey;
    }

    public int getSimpleKey() {
        return simpleKey;
    }

    public void setBase(int base) {
        this.base = base;
    }

    public void setModulus(int modulus) {
        this.modulus = modulus;
    }



}
