package novo;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

public class ModoCBC {
    public String decipher(String chave, String str) throws Exception {

        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());

        if (Security.getProvider("BCFIPS") == null) {
            System.out.println("Bouncy Castle provider NAO disponivel");
        } else {
            System.out.println("Bouncy Castle provider esta disponivel");
        }

//        String chave = "ea91381b3f8d8902b3ecb8a448a19a61";
        
        byte[] bytes = new BigInteger("7F" + chave, 16).toByteArray();
        SecretKeySpec aesKey = new SecretKeySpec(bytes, 1, bytes.length-1, "AES");

        System.out.println("Chave AES = " + Utils.toHex(aesKey.getEncoded()));

//        String str = "510a682f670960909cd36c234a78f11ba9034798269a41f2e881b87f373038ebe510fc118caa83d01ca6bcf2d1915243956f51ea8d3ef88d5e2b9350331de4a00a55f2335a72da45bc8ffee5520dc727";
        byte[] EcipherText = new BigInteger(str, 16).toByteArray();// HEX para BYTE
        System.out.println("str: " + str);
        byte[] Eiv = new BigInteger("01020304050607080910111213141516", 16).toByteArray();                                 // BYTE DO IV
//        byte[] EivS = new byte[EcipherText.length];//-16];
//        for (int i = 0, j = 0; i < 16; i++) {                      // RETIRANDO O IV
//            if(i < 16){
//            Eiv[i] = EcipherText[i];
//            }else{
//                EivS[j] = EcipherText[i];
//                j++;
//            }
//        }
        IvParameterSpec EivSpec = new IvParameterSpec(Eiv);
        System.out.println("ENCRIPT IV = " + Utils.toHex(Eiv));
        int EctLength = EcipherText.length;
        // Instanciando cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BCFIPS"); // PKCS5Padding = IV de 16 Bytes

        // PASSOS DE DESCRIPTOGRAFIA
        cipher.init(Cipher.DECRYPT_MODE, aesKey, EivSpec);

        byte[] buf = new byte[cipher.getOutputSize(EctLength)];

        int bufLength = cipher.update(EcipherText, 0, EctLength, buf, 0);

        bufLength += cipher.doFinal(buf, bufLength);

        // REMOVE O IV DO TEXTO ORIGINAL
        byte[] plainText = new byte[bufLength];// - Eiv.length];

        System.arraycopy(buf, Eiv.length, plainText, 0, plainText.length);

        System.out.println("SAIDA HEXADECIMAL: " + Utils.toHex(plainText, plainText.length) + " bytes: " + plainText.length);
        
        // TRANSFORMA��O PARA STRING
        String st = new String(plainText,StandardCharsets.UTF_8);
        System.out.println("SAIDA STRING: "+ st);
        
        return st;
    }
}
