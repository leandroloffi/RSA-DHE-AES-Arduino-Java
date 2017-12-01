import model.FDR;

public class StringHandler {

    private static final char SEPARATOR = '#';

    public static String convertByteToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }

        return sb.toString();
    }

    public static int getDiffieHellmanKeyClient(String sentence) {
        String dhKeyClient = "";

        for (int i = 0; i < sentence.length(); i++) {
            if (sentence.charAt(i) == SEPARATOR)
                break;
            dhKeyClient += sentence.charAt(i);
        }

        return Integer.parseInt(dhKeyClient);
    }

    public static int getBaseClient(String sentence) {
        String pClient = "";

        /* Avança até o primeiro divisor (#) da cadeia. */
        int i;
        for (i = 0; i < sentence.length(); i++) {
            if (sentence.charAt(i) == SEPARATOR)
                break;
        }
        i++;

        /* Recupera tudo o que está entre o primeiro e o segundo divisor (#). */
        for (int j = 0; j < sentence.length() - i; j++) {
            if (sentence.charAt(i) != SEPARATOR) {
                pClient += sentence.charAt(i);
                i++;
            }
        }
        return Integer.parseInt(pClient);
    }

    public static int getModulusClient(String sentence) {
        String gClient = "";

        /* Avança até o segundo divisor (#). */
        int i;
        int divisor = 0;
        for (i = 0; i < sentence.length(); i++) {
            if (sentence.charAt(i) == SEPARATOR)
                divisor++;

            if (divisor == 2)
                break;
        }
        i++;

        for (int j = 0; j < sentence.length() - i; j++) {
            if (sentence.charAt(i) != SEPARATOR) {
                gClient += sentence.charAt(i);
                i++;
            }
        }
        return Integer.parseInt(gClient);
    }

    public static int getIvDiffieHellmanClient(String sentence) {
        String ivDHClient = "";

        /* Avança até o terceiro divisor (#). */
        int i;
        int divisor = 0;
        for (i = 0; i < sentence.length(); i++) {
            if (sentence.charAt(i) == SEPARATOR)
                divisor++;

            if (divisor == 3)
                break;
        }
        i++;

        /* Recupera o iv do Client após o terceiro divisor (#). */
        for (int k = i; k < sentence.length(); k++) {
            if (sentence.charAt(k) != SEPARATOR)
                ivDHClient += sentence.charAt(k);
        }
        return Integer.parseInt(ivDHClient);
    }

    public static int getPublicKeyClient(String sentence) {
        String publicKeyClient = "";

        for (int i = 0; i < sentence.length(); i++) {
            if (sentence.charAt(i) == SEPARATOR)
                break;

            publicKeyClient += sentence.charAt(i);
        }

        return Integer.parseInt(publicKeyClient);
    }

    public static int getIvRSAExchange(String sentence) {
        String iv = "";

        /* Avança até o primeiro divisor (#). */
        int i = 0;
        for (i = 0; i < sentence.length(); i++) {
            if (sentence.charAt(i) == SEPARATOR)
                break;
        }
        i++;

        /* Recupera tudo aquilo que está depois do divisor (#). */
        for (int j = 0; j < sentence.length() - i; j++) {
            iv += sentence.charAt(i);
            i++;
            if (sentence.charAt(i) == SEPARATOR)
                break;
        }
        return Integer.parseInt(iv);
    }

    public static FDR getFdrRSAClient(String sentence) {
        char operator;
        String operand = "";

        /* Avança até o segundo divisor (#). */
        int i;
        int divisor = 0;
        for (i = 0; i < sentence.length(); i++) {
            if (sentence.charAt(i) == SEPARATOR)
                divisor++;

            if (divisor == 2)
                break;
        }
        i++;

        operator = sentence.charAt(i);
        for (i += 1; i<sentence.length(); i++)
            operand += sentence.charAt(i);

        return new FDR(operator, Integer.parseInt(operand));
    }
}
