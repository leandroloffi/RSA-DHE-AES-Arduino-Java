package novo;

public class KeyGenerator {
	
	private static final int b = 3;
	private int g;
	private int p;
	private int simpleKey;
	private static final int public_key = 8736;
	private static final int private_key = 3782;
	
	public int getKey() {
		return (int) Math.pow(g, b) % p;
	}
	
	public int getKeyG(int g) {
		return (int) Math.pow(g, b) % p;
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
	
	public void setG(int g) {
		this.g = g;
	}
	
	public void setP(int p) {
		this.p = p;
	}
	
	

}
